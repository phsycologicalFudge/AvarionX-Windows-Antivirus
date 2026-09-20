import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'services/rtp_service.dart';

class AvHomeScreen extends StatelessWidget {
  final bool visible;
  final void Function(String tab)? onNavigate;

  const AvHomeScreen({super.key, this.visible = true, this.onNavigate});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    return Scaffold(
      backgroundColor: theme.scaffoldBackgroundColor,
      body: Padding(
        padding: const EdgeInsets.fromLTRB(28, 28, 28, 28),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 520),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const _RtpToggleRow(),
                        const SizedBox(height: 14),
                        _FeatureRow(
                          icon: Icons.search_rounded,
                          title: 'Scan',
                          subtitle: 'Run a smart scan.',
                          color: cs.primary,
                          onTap: () => onNavigate?.call('scan'),
                        ),
                        const SizedBox(height: 10),
                        _FeatureRow(
                          icon: Icons.warning_amber_rounded,
                          title: 'Quarantine',
                          subtitle: 'View detected threats.',
                          color: Colors.redAccent,
                          onTap: () => onNavigate?.call('quarantine'),
                        ),
                        const SizedBox(height: 10),
                        _FeatureRow(
                          icon: Icons.receipt_long_rounded,
                          title: 'Realtime logs',
                          subtitle: 'Open the full event log.',
                          color: cs.secondary,
                          onTap: () => onNavigate?.call('rtp'),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 24),
                  Expanded(
                    child: _HomeLiveLogPanel(visible: visible),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 18),
            const SizedBox(width: double.infinity, child: Center(child: _AvarionXSecurityFooter())),
          ],
        ),
      ),
    );
  }
}

class _AvarionXSecurityFooter extends StatelessWidget {
  const _AvarionXSecurityFooter();

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final text = theme.textTheme;
    final cs = theme.colorScheme;

    return Opacity(
      opacity: theme.brightness == Brightness.dark ? 0.58 : 0.72,
      child: Column(
        children: [
          Text(
            'AvarionX',
            style: text.titleSmall?.copyWith(
              fontWeight: FontWeight.w800,
              letterSpacing: 0.4,
              color: cs.onSurface,
            ),
          ),
          const SizedBox(height: 3),
          Text(
            'Protected by X-SERIES',
            style: text.labelSmall?.copyWith(
              letterSpacing: 0.2,
              color: cs.onSurface.withOpacity(0.62),
            ),
          ),
        ],
      ),
    );
  }
}

class _FeatureRow extends StatelessWidget {
  final IconData icon;
  final String title;
  final String subtitle;
  final Color color;
  final VoidCallback onTap;

  const _FeatureRow({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.color,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;
    final text = theme.textTheme;

    return Material(
      color: theme.cardColor,
      borderRadius: BorderRadius.circular(16),
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: onTap,
        child: IntrinsicHeight(
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Container(
                width: 64,
                color: color.withOpacity(0.16),
                child: Icon(icon, color: color, size: 26),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Padding(
                  padding: const EdgeInsets.symmetric(vertical: 16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Text(
                        title,
                        style: text.titleSmall?.copyWith(fontWeight: FontWeight.w800),
                      ),
                      const SizedBox(height: 3),
                      Text(
                        subtitle,
                        style: text.bodySmall?.copyWith(
                          color: cs.onSurface.withOpacity(0.55),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              Padding(
                padding: const EdgeInsets.only(right: 14),
                child: Icon(
                  Icons.chevron_right_rounded,
                  size: 22,
                  color: cs.onSurface.withOpacity(0.35),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _RtpToggleRow extends StatefulWidget {
  const _RtpToggleRow();

  @override
  State<_RtpToggleRow> createState() => _RtpToggleRowState();
}

class _RtpToggleRowState extends State<_RtpToggleRow> {
  bool _enabled = false;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    _init();
  }

  Future<void> _init() async {
    final r = await RtpService.isRunning();
    if (!mounted) return;
    setState(() => _enabled = r);
  }

  Future<void> _setEnabled(bool v) async {
    if (_busy) return;
    setState(() => _busy = true);

    try {
      if (v) {
        await RtpService.enableProtection();
      } else {
        await RtpService.disableProtection();
      }
    } catch (_) {}

    final running = await RtpService.isRunning();
    if (!mounted) return;
    setState(() {
      _enabled = running;
      _busy = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;
    final text = theme.textTheme;
    final accent = _enabled ? Colors.greenAccent : Colors.redAccent;

    return Material(
      color: theme.cardColor,
      borderRadius: BorderRadius.circular(16),
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: _busy ? null : () => _setEnabled(!_enabled),
        child: IntrinsicHeight(
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              AnimatedContainer(
                duration: const Duration(milliseconds: 300),
                curve: Curves.easeInOut,
                width: 64,
                color: accent.withOpacity(0.16),
                child: Icon(
                  _enabled ? Icons.verified_user_rounded : Icons.shield_outlined,
                  color: accent,
                  size: 26,
                ),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Padding(
                  padding: const EdgeInsets.symmetric(vertical: 16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Text(
                        'Realtime Protection',
                        style: text.titleSmall?.copyWith(fontWeight: FontWeight.w800),
                      ),
                      const SizedBox(height: 3),
                      Text(
                        _enabled ? 'Enabled' : 'Disabled',
                        style: text.bodySmall?.copyWith(
                          color: cs.onSurface.withOpacity(0.55),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              Padding(
                padding: const EdgeInsets.only(right: 14),
                child: Switch(
                  value: _enabled,
                  onChanged: _busy ? null : _setEnabled,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _HomeLiveLogPanel extends StatefulWidget {
  final bool visible;

  const _HomeLiveLogPanel({this.visible = true});

  @override
  State<_HomeLiveLogPanel> createState() => _HomeLiveLogPanelState();
}

class _HomeLiveLogPanelState extends State<_HomeLiveLogPanel> {
  Timer? _timer;
  static const _refreshInterval = Duration(seconds: 2);

  static final _candidateLine = RegExp(r'^(\w+)\(pid=(\d+)\)\s+(\S+)\s+(.+)$');
  static final _downloadLine = RegExp(r'^(ok|MALICIOUS) download (?:session=\d+ )?(.+?)(?: quarantined=\w+)? verdict=(\{.*\})$');

  final List<_ProcLine> _items = [];

  DateTime? _lastModified;
  int _lastSize = 0;

  @override
  void initState() {
    super.initState();
    _load();
    _startTimer();
  }

  @override
  void didUpdateWidget(covariant _HomeLiveLogPanel old) {
    super.didUpdateWidget(old);
    if (widget.visible && !old.visible) {
      _load();
      _startTimer();
    } else if (!widget.visible && old.visible) {
      _timer?.cancel();
      _timer = null;
    }
  }

  void _startTimer() {
    _timer?.cancel();
    _timer = Timer.periodic(_refreshInterval, (_) => _load());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _load() async {
    final exeDir = File(Platform.resolvedExecutable).parent.path;
    final logFile = File('$exeDir/rtp_logs/rtp_main.log');

    try {
      if (!logFile.existsSync()) {
        if (_items.isNotEmpty && mounted) {
          setState(() {
            _items.clear();
            _lastModified = null;
            _lastSize = 0;
          });
        }
        return;
      }

      final stat = logFile.statSync();
      if (stat.modified == _lastModified && stat.size == _lastSize) return;
      _lastModified = stat.modified;
      _lastSize = stat.size;
    } catch (_) {
      return;
    }

    final next = <_ProcLine>[];

    try {
      final lines = const LineSplitter().convert(logFile.readAsStringSync());
      for (final raw in lines) {
        final line = raw.trim();
        if (line.isEmpty) continue;

        final time = _extractBracketTime(line);
        final msg = _stripBracketPrefix(line);

        if (msg.startsWith('watching:')) continue;

        final candidateMatch = _candidateLine.firstMatch(msg);
        if (candidateMatch != null) {
          final name = candidateMatch.group(3)!;
          next.add(_ProcLine(time: time, name: name));
          continue;
        }

        final downloadMatch = _downloadLine.firstMatch(msg);
        if (downloadMatch != null) {
          final exe = downloadMatch.group(2)!;
          final name = exe.split(RegExp(r'[\\/]')).last;
          next.add(_ProcLine(time: time, name: name));
        }
      }
    } catch (_) {}

    final seen = <String>{};
    final dedup = <_ProcLine>[];
    for (var i = next.length - 1; i >= 0 && dedup.length < 5; i--) {
      final k = next[i].name.toLowerCase();
      if (seen.add(k)) {
        dedup.add(next[i]);
      }
    }

    if (!mounted) return;
    setState(() {
      _items
        ..clear()
        ..addAll(dedup);
    });
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

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;
    final text = theme.textTheme;

    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: theme.cardColor,
        borderRadius: BorderRadius.circular(16),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Live activity',
            style: text.titleSmall?.copyWith(fontWeight: FontWeight.w800),
          ),
          const SizedBox(height: 14),
          if (_items.isEmpty)
            Text(
              'No named processes yet.',
              style: text.bodySmall?.copyWith(color: cs.onSurface.withOpacity(0.55)),
            )
          else
            for (var i = 0; i < _items.length; i++) ...[
              if (i > 0)
                Divider(
                  height: 1,
                  color: cs.onSurface.withOpacity(0.06),
                ),
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 10),
                child: Row(
                  children: [
                    Expanded(
                      child: Text(
                        _items[i].name,
                        style: text.bodyMedium?.copyWith(fontWeight: FontWeight.w700),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    if (_items[i].time.isNotEmpty)
                      Text(
                        _items[i].time,
                        style: text.bodySmall?.copyWith(color: cs.onSurface.withOpacity(0.45)),
                      ),
                  ],
                ),
              ),
            ],
        ],
      ),
    );
  }
}

class _ProcLine {
  final String time;
  final String name;

  const _ProcLine({required this.time, required this.name});
}