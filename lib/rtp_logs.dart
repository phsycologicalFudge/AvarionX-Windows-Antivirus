import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';

class RtpLogsScreen extends StatefulWidget {
  const RtpLogsScreen({super.key});

  @override
  State<RtpLogsScreen> createState() => _RtpLogsScreenState();
}

class _RtpLogsScreenState extends State<RtpLogsScreen> {
  bool _loading = true;
  Timer? _timer;

  static const _refreshInterval = Duration(seconds: 2);
  static const _maxLogLinesRead = 4000;

  static final _candidateLine = RegExp(r'^(\w+)\(pid=(\d+)\)\s+(\S+)\s+(.+)$');
  static final _downloadLine = RegExp(r'^(ok|MALICIOUS) download (.+?) verdict=(\{.*\})$');

  String? _readError;

  final List<_NameEvent> _feed = [];
  final List<_NameEvent> _detections = [];

  @override
  void initState() {
    super.initState();
    _loadLogs(initial: true);
    _timer = Timer.periodic(_refreshInterval, (_) => _loadLogs(initial: false));
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _loadLogs({required bool initial}) async {
    if (initial) {
      setState(() {
        _loading = true;
      });
    }

    final exeDir = File(Platform.resolvedExecutable).parent.path;
    final logsDir = Directory('$exeDir/rtp_logs');
    final logFile = File('${logsDir.path}/rtp_main.log');

    String? nextError;

    final nextFeed = <_NameEvent>[];
    final nextDetections = <_NameEvent>[];

    try {
      if (!logFile.existsSync()) {
        nextError = 'Missing file';
      } else {
        final allLines = const LineSplitter().convert(logFile.readAsStringSync());
        final lines = allLines.length > _maxLogLinesRead
            ? allLines.sublist(allLines.length - _maxLogLinesRead)
            : allLines;

        for (final raw in lines) {
          final line = raw.trim();
          if (line.isEmpty) continue;

          final time = _extractBracketTime(line);
          final msg = _stripBracketPrefix(line);

          if (msg.startsWith('watching:')) continue;

          final candidateMatch = _candidateLine.firstMatch(msg);
          if (candidateMatch != null) {
            final source = candidateMatch.group(1)!;
            final name = candidateMatch.group(3)!;
            final exe = candidateMatch.group(4)!;
            nextFeed.add(_NameEvent(
              time: time,
              name: name,
              subtitle: exe,
              source: source,
            ));
            continue;
          }

          final downloadMatch = _downloadLine.firstMatch(msg);
          if (downloadMatch != null) {
            final verdictWord = downloadMatch.group(1)!;
            final exe = downloadMatch.group(2)!;
            final name = exe.split(RegExp(r'[\\/]')).last;
            nextFeed.add(_NameEvent(
              time: time,
              name: name,
              subtitle: exe,
              source: 'download',
              flagged: verdictWord == 'MALICIOUS',
            ));
          }
        }
      }
    } catch (_) {
      nextError = 'Failed to read';
    }

    try {
      final detDir = Directory('${logsDir.path}/detections');
      if (detDir.existsSync()) {
        final files = detDir
            .listSync()
            .whereType<File>()
            .where((f) => f.path.endsWith('.json'))
            .toList()
          ..sort((a, b) => b.path.compareTo(a.path));

        for (final f in files) {
          try {
            final obj = jsonDecode(f.readAsStringSync());
            if (obj is! Map<String, dynamic>) continue;

            final name = (obj['name'] as String?)?.trim() ?? '';
            if (name.isEmpty) continue;

            final ts = obj['ts'];
            final time = ts is int ? _formatEpochMs(ts) : '';

            final exe = (obj['exe'] as String?) ?? '';
            final source = (obj['source'] as String?) ?? '';

            String? state;
            final verdict = obj['verdict'];
            if (verdict is Map) {
              state = (verdict['verdict'] as String?)?.trim();
            }

            final label = (obj['label'] as String?)?.trim();
            final shown = (label != null && label.isNotEmpty) ? label : state;

            nextDetections.add(_NameEvent(
              time: time,
              name: name,
              subtitle: shown == null ? exe : '$shown · $exe',
              source: source,
              flagged: true,
            ));
          } catch (_) {}
        }
      }
    } catch (_) {}

    if (!mounted) return;

    final dedupFeed = _dedupByNameKeepingLatest(nextFeed);
    final dedupDet = _dedupByKeepingLatest(nextDetections);

    setState(() {
      _readError = nextError;
      _feed
        ..clear()
        ..addAll(dedupFeed.take(120));
      _detections
        ..clear()
        ..addAll(dedupDet.take(80));
      _loading = false;
    });
  }

  static List<_NameEvent> _dedupByNameKeepingLatest(List<_NameEvent> items) {
    final seen = <String, _NameEvent>{};
    for (final e in items.reversed) {
      final key = e.name.toLowerCase();
      if (!seen.containsKey(key)) seen[key] = e;
    }
    final out = seen.values.toList();
    out.sort((a, b) => b.time.compareTo(a.time));
    return out;
  }

  static List<_NameEvent> _dedupByKeepingLatest(List<_NameEvent> items) {
    final out = List<_NameEvent>.from(items);
    out.sort((a, b) => b.time.compareTo(a.time));
    return out;
  }

  static String _extractBracketTime(String line) {
    if (!line.startsWith('[')) return '';
    final j = line.indexOf(']');
    if (j <= 1) return '';
    return line.substring(1, j).trim();
  }

  static String _stripBracketPrefix(String line) {
    if (!line.startsWith('[')) return line.trim();
    final j = line.indexOf(']');
    if (j == -1) return line.trim();
    return line.substring(j + 1).trim();
  }

  static String _formatEpochMs(int ms) {
    final d = DateTime.fromMillisecondsSinceEpoch(ms).toLocal();
    String two(int v) => v.toString().padLeft(2, '0');
    return '${d.year}-${two(d.month)}-${two(d.day)} ${two(d.hour)}:${two(d.minute)}:${two(d.second)}';
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    return Scaffold(
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : Padding(
        padding: const EdgeInsets.all(28),
        child: Row(
          children: [
            Expanded(
              flex: 1,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _FlatHeader(
                    title: 'Live activity',
                    subtitle: _readError == null ? '' : 'Log unavailable',
                  ),
                  const SizedBox(height: 10),
                  Expanded(
                    child: _feed.isEmpty
                        ? _FlatPanel(
                      child: Text(
                        'No named process events yet.',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: cs.onSurface.withOpacity(0.7),
                        ),
                      ),
                    )
                        : ListView.builder(
                      itemCount: _feed.length,
                      itemBuilder: (context, i) => _NameRow(event: _feed[i]),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              flex: 1,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const _FlatHeader(
                    title: 'Detections',
                    subtitle: '',
                  ),
                  const SizedBox(height: 10),
                  Expanded(
                    child: _detections.isEmpty
                        ? _FlatPanel(
                      child: Text(
                        'No detections.',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: cs.onSurface.withOpacity(0.7),
                        ),
                      ),
                    )
                        : ListView.builder(
                      itemCount: _detections.length,
                      itemBuilder: (context, i) => _NameRow(event: _detections[i]),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _FlatHeader extends StatelessWidget {
  final String title;
  final String subtitle;

  const _FlatHeader({
    required this.title,
    required this.subtitle,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w800),
        ),
        if (subtitle.isNotEmpty) ...[
          const SizedBox(height: 2),
          Text(
            subtitle,
            style: theme.textTheme.bodySmall?.copyWith(color: cs.error),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
        ],
      ],
    );
  }
}

class _FlatPanel extends StatelessWidget {
  final Widget child;

  const _FlatPanel({required this.child});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: cs.surface.withOpacity(0.55),
        borderRadius: BorderRadius.circular(16),
      ),
      child: child,
    );
  }
}

class _NameRow extends StatelessWidget {
  final _NameEvent event;

  const _NameRow({required this.event});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: cs.surface.withOpacity(0.55),
          borderRadius: BorderRadius.circular(14),
        ),
        child: Row(
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    event.name,
                    style: theme.textTheme.bodyMedium?.copyWith(
                      fontWeight: FontWeight.w700,
                      color: event.flagged ? cs.error : null,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  if (event.subtitle.isNotEmpty)
                    Text(
                      event.subtitle,
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: event.flagged ? cs.error.withOpacity(0.8) : cs.onSurface.withOpacity(0.6),
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                ],
              ),
            ),
            if (event.time.isNotEmpty)
              Text(
                event.time,
                style: theme.textTheme.bodySmall?.copyWith(color: cs.onSurface.withOpacity(0.6)),
              ),
          ],
        ),
      ),
    );
  }
}

class _NameEvent {
  final String time;
  final String name;
  final String subtitle;
  final String source;
  final bool flagged;

  const _NameEvent({
    required this.time,
    required this.name,
    this.subtitle = '',
    this.source = '',
    this.flagged = false,
  });
}