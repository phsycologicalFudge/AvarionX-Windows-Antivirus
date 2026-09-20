import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../../services/quarantine_service.dart';
import '../../services/exclusion_service.dart';

const double _leadWidth = 48;
const double _trailWidth = 48;
const double _cellPad = 10;

class QuarantineScreen extends StatefulWidget {
  const QuarantineScreen({super.key});

  @override
  State<QuarantineScreen> createState() => _QuarantineScreenState();
}

class _QuarantineScreenState extends State<QuarantineScreen> {
  List<Map<String, dynamic>> items = [];
  final Set<String> selected = {};
  bool loading = true;
  bool restoring = false;
  String? error;

  @override
  void initState() {
    super.initState();
    _reload();
  }

  Future<void> _reload() async {
    setState(() {
      loading = true;
      error = null;
    });
    try {
      final data = await QuarantineService.listAll();
      if (!mounted) return;
      setState(() {
        items = data;
        selected.clear();
      });
    } catch (e) {
      if (!mounted) return;
      setState(() => error = '$e');
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  void _toggleSelect(String id) {
    setState(() {
      if (selected.contains(id)) {
        selected.remove(id);
      } else {
        selected.add(id);
      }
    });
  }

  void _selectAll() {
    setState(() {
      if (selected.length == items.length) {
        selected.clear();
      } else {
        selected
          ..clear()
          ..addAll(items.map((e) => e['id'] as String));
      }
    });
  }

  Future<void> _restoreSelected() async {
    if (selected.isEmpty) return;
    setState(() => restoring = true);
    try {
      await QuarantineService.restoreManyIsolated(selected);
      await _reload();
    } finally {
      if (mounted) setState(() => restoring = false);
    }
  }

  Future<void> _deleteSelected() async {
    if (selected.isEmpty) return;

    for (final id in selected) {
      try {
        await QuarantineService.deleteForever(id);
      } catch (_) {}
    }

    await _reload();
  }
  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final text = theme.textTheme;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Quarantine'),
        actions: [
          IconButton(
            icon: const Icon(Icons.select_all_rounded),
            tooltip: 'Select all',
            onPressed: items.isEmpty ? null : _selectAll,
          ),
          IconButton(
            icon: const Icon(Icons.refresh_rounded),
            tooltip: 'Refresh',
            onPressed: _reload,
          ),
        ],
      ),
      body: Stack(
        children: [
          if (loading)
            const Center(child: CircularProgressIndicator())
          else if (error != null)
            Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      'Could not load quarantine',
                      style: text.titleSmall?.copyWith(fontWeight: FontWeight.w800),
                    ),
                    const SizedBox(height: 8),
                    Text(error!, textAlign: TextAlign.center),
                    const SizedBox(height: 12),
                    ElevatedButton(onPressed: _reload, child: const Text('Try again')),
                  ],
                ),
              ),
            )
          else if (items.isEmpty)
              Center(
                child: Text(
                  'Quarantine is empty',
                  style: text.bodyMedium?.copyWith(
                    color: text.bodyMedium?.color?.withOpacity(0.7),
                  ),
                ),
              )
            else
              Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  children: [
                    _buildHeader(theme),
                    const Divider(height: 1),
                    Expanded(child: _buildTable(theme)),
                  ],
                ),
              ),
          if (restoring)
            Positioned.fill(
              child: AbsorbPointer(
                child: Container(
                  color: Colors.black.withOpacity(0.45),
                  child: const Center(child: CircularProgressIndicator()),
                ),
              ),
            ),
        ],
      ),
      bottomNavigationBar: items.isEmpty
          ? null
          : Padding(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
        child: Row(
          children: [
            Expanded(
              child: ElevatedButton.icon(
                onPressed: selected.isEmpty ? null : _restoreSelected,
                icon: const Icon(Icons.restore_rounded),
                label: const Text('Restore'),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: ElevatedButton.icon(
                onPressed: selected.isEmpty ? null : _deleteSelected,
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.redAccent,
                  foregroundColor: Colors.white,
                ),
                icon: const Icon(Icons.delete_forever_rounded),
                label: const Text('Delete'),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _cell(int flex, Widget child) {
    return Expanded(
      flex: flex,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: _cellPad),
        child: child,
      ),
    );
  }

  Widget _ellipsis(String value, {TextStyle? style, bool tooltip = false}) {
    final t = Text(
      value,
      maxLines: 1,
      softWrap: false,
      overflow: TextOverflow.ellipsis,
      style: style,
    );
    if (tooltip && value.isNotEmpty) return Tooltip(message: value, child: t);
    return t;
  }

  Widget _buildHeader(ThemeData theme) {
    const style = TextStyle(fontWeight: FontWeight.w700);
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        children: [
          const SizedBox(width: _leadWidth),
          _cell(3, _ellipsis('Name', style: style)),
          _cell(3, _ellipsis('Threat name', style: style)),
          _cell(4, _ellipsis('Original location', style: style)),
          _cell(3, _ellipsis('Date', style: style)),
          const SizedBox(width: _trailWidth),
        ],
      ),
    );
  }

  Widget _buildTable(ThemeData theme) {
    final df = DateFormat.yMMMd().add_jm();

    return ListView.separated(
      itemCount: items.length,
      separatorBuilder: (_, __) => const Divider(height: 1),
      itemBuilder: (context, i) {
        final m = items[i];
        final id = m['id'] as String;
        final sel = selected.contains(id);

        return InkWell(
          onTap: () => _toggleSelect(id),
          child: Container(
            padding: const EdgeInsets.symmetric(vertical: 10),
            color: sel ? theme.colorScheme.primary.withOpacity(0.08) : null,
            child: Row(
              children: [
                SizedBox(
                  width: _leadWidth,
                  child: Center(
                    child: Checkbox(
                      value: sel,
                      onChanged: (_) => _toggleSelect(id),
                    ),
                  ),
                ),
                _cell(3, _ellipsis('${m['name'] ?? 'Unknown'}', tooltip: true)),
                _cell(
                  3,
                  _ellipsis(
                    (m['label']?.toString() ?? '').isEmpty ? '-' : '${m['label']}',
                    style: const TextStyle(
                      fontWeight: FontWeight.w600,
                      color: Colors.orangeAccent,
                    ),
                    tooltip: true,
                  ),
                ),
                _cell(
                  4,
                  _ellipsis(
                    '${m['originalPath'] ?? ''}',
                    style: TextStyle(color: theme.textTheme.bodySmall?.color),
                    tooltip: true,
                  ),
                ),
                _cell(3, _ellipsis(df.format(DateTime.parse(m['date'])))),
                SizedBox(
                  width: _trailWidth,
                  child: Center(
                    child: IconButton(
                      tooltip: 'Exclude hash',
                      icon: const Icon(Icons.block, color: Colors.orange),
                      onPressed: () async {
                        final sha = await QuarantineService.shaFor(m);
                        if (sha == null) return;
                        final x = ExclusionService();
                        await x.load();
                        await x.addSha(sha);
                      },
                    ),
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}