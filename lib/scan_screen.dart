import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';
import '../services/cache_manager.dart';
import '../services/cloud/cloud_auth_service.dart';
import '../services/cloud_helper_service.dart';
import '../services/quarantine_service.dart';
import '../utils/hash_cache_worker.dart';
import 'core/antivirus_bridge.dart';

const _cloudEligibleExtensions = {'.apk', '.exe', '.dll', '.msi'};

enum ScanMode { smart, single, custom, pc }
enum ScanState { idle, scanning, result }

const _redundantPlatformTokens = {'android'};

List<String> _dropRedundantPlatform(List<String> parts) {
  if (parts.isNotEmpty && _redundantPlatformTokens.contains(parts.first.toLowerCase())) {
    return parts.sublist(1);
  }
  return parts;
}

String parseSigName(String raw) {
  if (raw.isEmpty) return 'Suspicious.Item';

  final parts = raw.split('.');
  const noise = {'androidos', 'and', 'byte', 'simple', 'complex'};

  if (parts.length >= 3 &&
      parts[0].toLowerCase() == 'androidos' &&
      parts[2].toLowerCase() == 'origin') {
    return 'Andr/${parts[1]}.Origin';
  }

  if (parts.length >= 4 && parts[2].toLowerCase() == 'androidos') {
    final keep = <String>[];
    for (final p in parts) {
      final lo = p.toLowerCase();
      if (noise.contains(lo)) continue;
      if (RegExp(r'^\d+$').hasMatch(p)) continue;
      keep.add(p);
    }
    final trimmed = _dropRedundantPlatform(keep);
    return trimmed.isNotEmpty ? trimmed.join('.') : raw;
  }

  if (parts.length >= 3 && parts[2].toLowerCase() == 'byte') {
    final platform = parts[0];
    final categoryRaw = parts[1];
    final categoryParts = categoryRaw.split('_');
    final keep = _dropRedundantPlatform(<String>[platform, ...categoryParts]);
    return keep.isNotEmpty ? keep.join('.') : raw;
  }

  final keep = <String>[];
  for (final p in parts) {
    final lo = p.toLowerCase();
    if (noise.contains(lo)) continue;
    if (RegExp(r'^\d+$').hasMatch(p)) continue;
    keep.add(p);
  }
  final trimmed = _dropRedundantPlatform(keep);
  return trimmed.isNotEmpty ? trimmed.join('.') : raw;
}

bool isApkPath(String path) => path.toLowerCase().endsWith('.apk');

bool isHashSignal(List<String> signals) {
  return signals.contains('HashMatch') ||
      signals.any((s) => s.startsWith('SignerMatch('));
}

bool isMlSignal(List<String> signals) {
  return signals.any((s) => s.startsWith('ML_Detection('));
}

String structuredHashLabel(String path) {
  if (isApkPath(path)) return 'Android.KnownMalware.HashMatch';
  return 'Generic.KnownMalware.HashMatch';
}

String structuredSignatureLabel(String raw) {
  return parseSigName(raw);
}

Future<void> showScanDialog(
    BuildContext context, {
      ScanMode? startMode,
      VoidCallback? onOpenQuarantine,
    }) {
  return showDialog(
    context: context,
    barrierDismissible: true,
    builder: (dialogContext) {
      final theme = Theme.of(dialogContext);

      return Dialog(
        backgroundColor: theme.cardColor,
        clipBehavior: Clip.antiAlias,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(20),
        ),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 460),
          child: Stack(
            children: [
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: ScanScreen(
                  embedded: true,
                  startMode: startMode,
                  onOpenQuarantine: onOpenQuarantine,
                ),
              ),
              Positioned(
                top: 6,
                right: 6,
                child: IconButton(
                  icon: const Icon(Icons.close_rounded),
                  onPressed: () => Navigator.of(dialogContext).pop(),
                ),
              ),
            ],
          ),
        ),
      );
    },
  );
}

class DetectionResult {
  final String name;
  final String label;
  final double confidence;
  final List<String> signals;

  DetectionResult({
    required this.name,
    required this.label,
    required this.confidence,
    required this.signals,
  });
}

class ScanScreen extends StatefulWidget {
  final ScanMode? startMode;
  final VoidCallback? onReturnHome;
  final VoidCallback? onOpenQuarantine;
  final bool embedded;

  const ScanScreen({
    super.key,
    this.startMode,
    this.onReturnHome,
    this.onOpenQuarantine,
    this.embedded = false,
  });

  @override
  State<ScanScreen> createState() => _ScanScreenState();
}

class _ScanScreenState extends State<ScanScreen> {
  ScanState state = ScanState.idle;
  ScanMode mode = ScanMode.smart;

  bool _scanning = false;
  bool _busy = false;

  int total = 0;
  int infectedCount = 0;
  int cleanCount = 0;

  String targetPath = '';
  int targetBytes = 0;

  final List<DetectionResult> infected = [];

  final List<String> logs = [];
  final ScrollController _logScroll = ScrollController();

  ScanWorker? _worker;
  Timer? _uiTimer;

  DateTime? _scanStart;
  Duration _eta = Duration.zero;
  double _progress = 0.0;

  @override
  void initState() {
    super.initState();

    WidgetsBinding.instance.addPostFrameCallback((_) async {
      if (!mounted) return;
      final m = widget.startMode;
      if (m == null) return;
      mode = m;
      await _startScan(m);
    });
  }

  @override
  void dispose() {
    _uiTimer?.cancel();
    _worker?.dispose();
    _logScroll.dispose();
    super.dispose();
  }

  void _pushLog(String msg) {
    logs.add(msg);
    if (logs.length > 200) logs.removeAt(0);
    if (mounted) {
      setState(() {});
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (_logScroll.hasClients) {
          _logScroll.jumpTo(_logScroll.position.maxScrollExtent);
        }
      });
    }
  }

  void _resetUi() {
    total = 0;
    infectedCount = 0;
    cleanCount = 0;
    targetPath = '';
    targetBytes = 0;
    infected.clear();
    logs.clear();
    _scanStart = null;
    _eta = Duration.zero;
    _progress = 0.0;
  }

  void _handleBack() {
    if (state == ScanState.idle) {
      if (!widget.embedded) {
        widget.onReturnHome?.call();
        Navigator.maybePop(context);
      }
      return;
    }
    _cancelScan(goIdle: true);
  }

  void _cancelScan({required bool goIdle}) {
    _scanning = false;
    _busy = false;
    _uiTimer?.cancel();
    _uiTimer = null;
    _worker?.dispose();
    _worker = null;

    if (!mounted) return;

    if (goIdle) {
      setState(() {
        state = ScanState.idle;
        _resetUi();
      });
    }
  }

  Map<String, dynamic> _deriveVerdict(List<String> signals, String path) {
    if (isHashSignal(signals)) {
      return {
        'label': structuredHashLabel(path),
        'confidence': 1.0,
      };
    }

    final signature = signals.firstWhere(
          (s) => !s.startsWith('ML_Detection(') && s != 'HashMatch' && !s.startsWith('SignerMatch('),
      orElse: () => '',
    );

    if (signature.isNotEmpty) {
      return {
        'label': structuredSignatureLabel(signature),
        'confidence': 0.95,
      };
    }

    if (isMlSignal(signals) && isApkPath(path)) {
      return {
        'label': 'Andr/VXgen2',
        'confidence': 0.80,
      };
    }

    return {
      'label': 'Suspicious.Item',
      'confidence': 0.70,
    };
  }

  Future<_EnumResult> _enumerateAndSize(String path) async {
    final type = FileSystemEntity.typeSync(path);

    if (type == FileSystemEntityType.file) {
      try {
        final f = File(path);
        final len = await f.length();
        return _EnumResult(files: [path], totalBytes: len);
      } catch (_) {
        return _EnumResult(files: [path], totalBytes: 0);
      }
    }

    final files = <String>[];
    int bytes = 0;

    try {
      final dir = Directory(path);
      await for (final entity in dir.list(recursive: true, followLinks: false)) {
        if (entity is File) {
          files.add(entity.path);
          try {
            bytes += await entity.length();
          } catch (_) {}
        }
      }
    } catch (_) {}

    return _EnumResult(files: files, totalBytes: bytes);
  }

  Duration _estimateEtaFromBytes(int bytes, int fileCount) {
    if (bytes <= 0) return const Duration(seconds: 3);

    final gb = bytes / (1024 * 1024 * 1024);
    final minutes = gb * 0.2;
    var secs = minutes * 60;

    if (fileCount <= 200) secs *= 0.55;
    if (fileCount <= 50) secs *= 0.40;

    secs = secs.clamp(3.0, 60.0 * 60.0 * 24.0);
    return Duration(seconds: secs.round());
  }

  void _startUiTicker() {
    _uiTimer?.cancel();
    _uiTimer = Timer.periodic(const Duration(milliseconds: 250), (_) {
      if (!_scanning || _scanStart == null) return;

      final elapsed = DateTime.now().difference(_scanStart!);
      final etaSecs = _eta.inSeconds;
      if (etaSecs <= 0) return;

      final denom = _eta.inMilliseconds == 0 ? 1 : _eta.inMilliseconds;
      final p = (elapsed.inMilliseconds / denom).clamp(0.0, 0.995);

      if (!mounted) return;
      setState(() {
        _progress = p;
      });
    });
  }

  Future<void> _startScan(ScanMode m) async {
    if (_busy) return;
    _busy = true;

    _scanning = true;
    setState(() {
      state = ScanState.scanning;
      _resetUi();
    });

    String? pickedPath;

    if (m == ScanMode.single) {
      final res = await FilePicker.platform.pickFiles();
      pickedPath = res?.files.single.path;
    } else if (m == ScanMode.custom) {
      pickedPath = await FilePicker.platform.getDirectoryPath();
    } else if (m == ScanMode.pc) {
      pickedPath = Platform.isWindows ? 'C:\\' : '/';
    } else {
      pickedPath = Platform.environment['HOME'] ?? Platform.environment['USERPROFILE'];
    }

    if (!_scanning || !mounted) return;

    if (pickedPath == null || pickedPath.isEmpty) {
      _busy = false;
      _cancelScan(goIdle: true);
      return;
    }

    targetPath = pickedPath;

    _pushLog('Starting scan');
    _pushLog('Target: $targetPath');

    final enumRes = await _enumerateAndSize(targetPath);
    if (!_scanning || !mounted) return;

    total = enumRes.files.length;
    targetBytes = enumRes.totalBytes;

    _eta = _estimateEtaFromBytes(targetBytes, total);
    _scanStart = DateTime.now();
    _progress = 0.0;

    _pushLog('Files: $total');
    _pushLog('Estimated time: ${_fmtDuration(_eta)}');

    _startUiTicker();

    final cloudHitsFuture = _findCloudHits(enumRes.files);

    _worker?.dispose();
    _worker = await ScanWorker.spawn();

    final res = await _worker!.scan(targetPath);
    if (!_scanning || !mounted) return;

    final cloudHitPaths = await cloudHitsFuture;

    infected.clear();

    if (res != null) {
      final hits = res['hits'];
      if (hits is Map) {
        for (final entry in hits.entries) {
          final k = entry.key.toString();
          final v = entry.value;

          final displayName = k.contains(Platform.pathSeparator)
              ? k.split(Platform.pathSeparator).last
              : k;

          final signals = v is List ? v.map((e) => e.toString()).toList() : <String>[];

          final verdict = _deriveVerdict(signals, k.split('::').first);

          infected.add(
            DetectionResult(
              name: displayName,
              label: verdict['label'],
              confidence: verdict['confidence'],
              signals: signals,
            ),
          );

          if (!k.contains('::')) {
            try {
              final f = File(k);
              if (await f.exists()) {
                unawaited(
                  QuarantineService.quarantineFile(
                    k,
                    label: verdict['label'],
                    confidence: verdict['confidence'],
                  ),
                );
              }
            } catch (_) {}
          }
        }
      }
    }

    final nativeHitPaths = (res?['hits'] is Map)
        ? (res!['hits'] as Map).keys.map((k) => k.toString()).toSet()
        : <String>{};

    for (final path in cloudHitPaths) {
      if (nativeHitPaths.contains(path)) continue;

      final displayName = path.contains(Platform.pathSeparator)
          ? path.split(Platform.pathSeparator).last
          : path;

      infected.add(
        DetectionResult(
          name: displayName,
          label: structuredHashLabel(path),
          confidence: 1.0,
          signals: const ['HashMatch'],
        ),
      );

      try {
        final f = File(path);
        if (await f.exists()) {
          unawaited(
            QuarantineService.quarantineFile(
              path,
              label: structuredHashLabel(path),
              confidence: 1.0,
            ),
          );
        }
      } catch (_) {}
    }

    infectedCount = infected.length;
    cleanCount = (total - infectedCount).clamp(0, total);

    await CacheManager.clearAll();
    if (!_scanning || !mounted) return;

    _uiTimer?.cancel();
    _uiTimer = null;

    setState(() {
      _progress = 1.0;
      state = ScanState.result;
    });

    _scanning = false;
    _busy = false;
    _worker?.dispose();
    _worker = null;
  }

  Future<Set<String>> _findCloudHits(List<String> files) async {
    final eligible = files.where((p) {
      final dot = p.lastIndexOf('.');
      if (dot < 0) return false;
      return _cloudEligibleExtensions.contains(p.substring(dot).toLowerCase());
    }).toList();

    if (eligible.isEmpty) return const {};

    HashCacheWorker? hashWorker;
    try {
      final dir = await getApplicationSupportDirectory();
      hashWorker = await HashCacheWorker.spawn('${dir.path}/hashcache.bin');

      final hashes = await hashWorker.hashBatch(eligible);
      if (hashes.isEmpty) return const {};

      final hashToPath = <String, String>{};
      hashes.forEach((path, pair) {
        final md5 = pair['md5'] ?? '';
        final sha = pair['sha'] ?? '';
        if (md5.isNotEmpty) hashToPath[md5] = path;
        if (sha.isNotEmpty) hashToPath[sha] = path;
      });

      if (hashToPath.isEmpty) return const {};

      final cloud = CloudScanner(
        endpoint: 'https://api.colourswift.com/hash_cloud',
        apiKey: CloudAuthService.sessionToken ?? '',
      );

      final hits = await cloud.checkBatch(hashToPath.keys.toList());
      final hitPaths = <String>{};
      for (final h in hits) {
        final path = hashToPath[h];
        if (path != null) hitPaths.add(path);
      }
      return hitPaths;
    } catch (_) {
      return const {};
    } finally {
      await hashWorker?.close();
    }
  }

  static String _fmtDuration(Duration d) {
    if (d.inSeconds < 60) return '${d.inSeconds}s';
    final m = d.inMinutes;
    final s = d.inSeconds % 60;
    if (m < 60) return '${m}m ${s}s';
    final h = d.inHours;
    final rm = d.inMinutes % 60;
    return '${h}h ${rm}m';
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final text = theme.textTheme;
    final cs = theme.colorScheme;

    final body = Padding(
      padding: const EdgeInsets.all(24),
      child: switch (state) {
        ScanState.idle => _buildIdle(theme, text, cs),
        ScanState.scanning => _buildScanning(theme, text, cs),
        ScanState.result => _buildResult(theme, text, cs),
      },
    );

    if (widget.embedded) {
      return body;
    }

    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: _handleBack,
        ),
        title: const Text('Scan'),
      ),
      backgroundColor: theme.scaffoldBackgroundColor,
      body: body,
    );
  }

  Widget _buildIdle(ThemeData theme, TextTheme text, ColorScheme cs) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Choose scan type',
          style: text.titleMedium?.copyWith(fontWeight: FontWeight.w900),
        ),
        const SizedBox(height: 12),
        Wrap(
          spacing: 12,
          runSpacing: 12,
          children: [
            _ScanButton(
              icon: Icons.insert_drive_file_rounded,
              title: 'Scan file',
              onTap: () async {
                mode = ScanMode.single;
                await _startScan(mode);
              },
            ),
            _ScanButton(
              icon: Icons.folder_rounded,
              title: 'Scan folder',
              onTap: () async {
                mode = ScanMode.custom;
                await _startScan(mode);
              },
            ),
            _ScanButton(
              icon: Icons.computer_rounded,
              title: 'Scan PC',
              onTap: () async {
                mode = ScanMode.pc;
                await _startScan(mode);
              },
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildScanning(ThemeData theme, TextTheme text, ColorScheme cs) {
    final elapsed = _scanStart == null ? Duration.zero : DateTime.now().difference(_scanStart!);
    final remain = _eta.inSeconds <= 0
        ? Duration.zero
        : Duration(seconds: (_eta.inSeconds - elapsed.inSeconds).clamp(0, _eta.inSeconds));

    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Scanning',
          style: text.titleLarge?.copyWith(fontWeight: FontWeight.w900),
        ),
        const SizedBox(height: 6),
        Text(
          targetPath,
          style: text.bodySmall?.copyWith(color: cs.onSurface.withOpacity(0.65)),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
        const SizedBox(height: 14),
        LinearProgressIndicator(value: _progress),
        const SizedBox(height: 10),
        Row(
          children: [
            Expanded(
              child: Text(
                'ETA: ${_fmtDuration(remain)}',
                style: text.bodySmall?.copyWith(color: cs.onSurface.withOpacity(0.75)),
              ),
            ),
            Text(
              '${(_progress * 100).floor()}%',
              style: text.bodySmall?.copyWith(
                color: cs.onSurface.withOpacity(0.75),
                fontWeight: FontWeight.w800,
              ),
            ),
            const SizedBox(width: 12),
            TextButton.icon(
              onPressed: () => _cancelScan(goIdle: true),
              icon: const Icon(Icons.stop_rounded),
              label: const Text('Stop'),
            ),
          ],
        ),
        const SizedBox(height: 14),
        SizedBox(
          height: 260,
          child: Container(
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: cs.surface.withOpacity(0.55),
              borderRadius: BorderRadius.circular(16),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Activity',
                  style: text.titleSmall?.copyWith(fontWeight: FontWeight.w900),
                ),
                const SizedBox(height: 10),
                Expanded(
                  child: ListView.builder(
                    controller: _logScroll,
                    itemCount: logs.length,
                    itemBuilder: (_, i) {
                      return Padding(
                        padding: const EdgeInsets.only(bottom: 6),
                        child: Text(
                          logs[i],
                          style: text.bodySmall?.copyWith(
                            color: cs.onSurface.withOpacity(0.75),
                          ),
                        ),
                      );
                    },
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildResult(ThemeData theme, TextTheme text, ColorScheme cs) {
    final hasThreats = infectedCount > 0;

    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Scan complete',
          style: text.titleLarge?.copyWith(fontWeight: FontWeight.w900),
        ),
        const SizedBox(height: 10),
        Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: cs.surface.withOpacity(0.55),
            borderRadius: BorderRadius.circular(16),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _kv(text, cs, 'Files scanned', total.toString()),
              const SizedBox(height: 6),
              _kv(text, cs, 'Clean', cleanCount.toString()),
              const SizedBox(height: 6),
              _kv(text, cs, 'Threats', infectedCount.toString(), danger: hasThreats),
            ],
          ),
        ),
        if (hasThreats) ...[
          const SizedBox(height: 14),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
            decoration: BoxDecoration(
              color: cs.surface.withOpacity(0.55),
              borderRadius: BorderRadius.circular(16),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                for (var i = 0; i < infected.length; i++) ...[
                  if (i > 0)
                    Divider(
                      height: 1,
                      color: cs.onSurface.withOpacity(0.08),
                    ),
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 10),
                    child: Row(
                      children: [
                        Icon(
                          Icons.warning_amber_rounded,
                          size: 18,
                          color: cs.error,
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                infected[i].name,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: text.bodyMedium?.copyWith(
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                              const SizedBox(height: 2),
                              Text(
                                infected[i].label,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: text.bodySmall?.copyWith(
                                  color: cs.error.withOpacity(0.9),
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ],
            ),
          ),
        ],
        const SizedBox(height: 14),
        Row(
          children: [
            FilledButton(
              style: FilledButton.styleFrom(
                elevation: 0,
              ),
              onPressed: () {
                if (hasThreats) {
                  if (widget.embedded) {
                    Navigator.of(context).pop();
                  }
                  widget.onOpenQuarantine?.call();
                } else {
                  _cancelScan(goIdle: true);
                }
              },
              child: Text(hasThreats ? 'Open quarantine' : 'New scan'),
            ),
            const SizedBox(width: 10),
            TextButton(
              onPressed: () {
                if (widget.embedded) {
                  _cancelScan(goIdle: true);
                } else {
                  widget.onReturnHome?.call();
                  Navigator.maybePop(context);
                }
              },
              child: const Text('Back'),
            ),
          ],
        ),
      ],
    );
  }

  Widget _kv(TextTheme text, ColorScheme cs, String k, String v, {bool danger = false}) {
    return Row(
      children: [
        Expanded(
          child: Text(
            k,
            style: text.bodySmall?.copyWith(
              color: cs.onSurface.withOpacity(0.7),
              fontWeight: FontWeight.w700,
            ),
          ),
        ),
        Text(
          v,
          style: text.bodyMedium?.copyWith(
            fontWeight: FontWeight.w900,
            color: danger ? cs.error : cs.onSurface.withOpacity(0.9),
          ),
        ),
      ],
    );
  }
}

class _ScanButton extends StatelessWidget {
  final IconData icon;
  final String title;
  final VoidCallback onTap;

  const _ScanButton({
    required this.icon,
    required this.title,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    return Material(
      color: cs.surface.withOpacity(0.55),
      borderRadius: BorderRadius.circular(16),
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(16),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(icon, size: 20, color: cs.primary),
              const SizedBox(width: 10),
              Text(
                title,
                style: theme.textTheme.bodyMedium?.copyWith(fontWeight: FontWeight.w900),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _EnumResult {
  final List<String> files;
  final int totalBytes;

  const _EnumResult({required this.files, required this.totalBytes});
}

class ScanWorker {
  final SendPort sendPort;
  final Isolate _isolate;

  ScanWorker._(this.sendPort, this._isolate);

  static Future<ScanWorker> spawn() async {
    final receive = ReceivePort();
    final isolate = await Isolate.spawn(_entry, receive.sendPort);
    final send = await receive.first as SendPort;
    receive.close();
    return ScanWorker._(send, isolate);
  }

  static void _entry(SendPort root) {
    final port = ReceivePort();
    root.send(port.sendPort);

    port.listen((msg) {
      final send = msg[0] as SendPort;
      final path = msg[1] as String;

      try {
        final bridge = AntivirusBridge();
        final raw = bridge.scanFile(path);
        final decoded = jsonDecode(raw);
        final hits = decoded['hits'] as Map?;
        if (hits == null || hits.isEmpty) {
          send.send(null);
        } else {
          send.send({'hits': hits});
        }
      } catch (_) {
        send.send(null);
      }
    });
  }

  Future<dynamic> scan(String path) async {
    final port = ReceivePort();
    sendPort.send([port.sendPort, path]);

    final result = await port.first.timeout(
      const Duration(minutes: 60),
      onTimeout: () => null,
    );

    port.close();
    return result;
  }

  void dispose() {
    try {
      _isolate.kill(priority: Isolate.immediate);
    } catch (_) {}
  }
}