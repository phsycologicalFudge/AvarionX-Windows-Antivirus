import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'services/theme_manager.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    return Scaffold(
      backgroundColor: theme.scaffoldBackgroundColor,
      body: Padding(
        padding: const EdgeInsets.all(28),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 640),
          child: ListView(
            children: [
              _SettingsSection(
                title: 'Appearance',
                subtitle: 'Choose a theme.',
                child: const _ThemePicker(),
              ),
              const SizedBox(height: 18),
              _SettingsSection(
                title: 'Language',
                subtitle: 'Only English rn.',
                child: _LanguageRow(cs: cs),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _SettingsSection extends StatelessWidget {
  final String title;
  final String subtitle;
  final Widget child;

  const _SettingsSection({
    required this.title,
    required this.subtitle,
    required this.child,
  });

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
        crossAxisAlignment: CrossAxisAlignment.start,
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
          const SizedBox(height: 16),
          child,
        ],
      ),
    );
  }
}

class _ThemePicker extends StatelessWidget {
  const _ThemePicker();

  static const _options = [
    _ThemeOption(name: 'white', label: 'White', swatch: Color(0xFFF6F7F8)),
    _ThemeOption(name: 'black', label: 'Black', swatch: Color(0xFF101012)),
  ];

  @override
  Widget build(BuildContext context) {
    final themeManager = context.watch<ThemeManager>();
    final theme = Theme.of(context);
    final cs = theme.colorScheme;
    final text = theme.textTheme;

    return Wrap(
      spacing: 16,
      runSpacing: 16,
      children: _options.map((opt) {
        final selected = themeManager.themeName == opt.name;

        return InkWell(
          borderRadius: BorderRadius.circular(14),
          onTap: () => themeManager.setTheme(opt.name),
          child: Container(
            width: 92,
            padding: const EdgeInsets.symmetric(vertical: 12),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(14),
              border: Border.all(
                color: selected ? cs.primary : cs.onSurface.withOpacity(0.12),
                width: selected ? 2 : 1,
              ),
            ),
            child: Column(
              children: [
                Container(
                  width: 34,
                  height: 34,
                  decoration: BoxDecoration(
                    color: opt.swatch,
                    shape: BoxShape.circle,
                    border: Border.all(
                      color: cs.onSurface.withOpacity(0.18),
                    ),
                  ),
                  child: selected
                      ? Icon(
                    Icons.check_rounded,
                    size: 18,
                    color: opt.swatch.computeLuminance() > 0.5
                        ? Colors.black
                        : Colors.white,
                  )
                      : null,
                ),
                const SizedBox(height: 8),
                Text(
                  opt.label,
                  style: text.bodySmall?.copyWith(
                    fontWeight: selected ? FontWeight.w800 : FontWeight.w600,
                  ),
                ),
              ],
            ),
          ),
        );
      }).toList(),
    );
  }
}

class _ThemeOption {
  final String name;
  final String label;
  final Color swatch;

  const _ThemeOption({
    required this.name,
    required this.label,
    required this.swatch,
  });
}

class _LanguageRow extends StatelessWidget {
  final ColorScheme cs;

  const _LanguageRow({required this.cs});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final text = theme.textTheme;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      decoration: BoxDecoration(
        color: cs.onSurface.withOpacity(0.05),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        children: [
          Icon(Icons.language_rounded, size: 20, color: cs.onSurface.withOpacity(0.65)),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              'English',
              style: text.bodyMedium?.copyWith(fontWeight: FontWeight.w700),
            ),
          ),
          Icon(Icons.check_rounded, size: 18, color: cs.primary),
        ],
      ),
    );
  }
}