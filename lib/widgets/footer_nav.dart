import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/theme_manager.dart';
import 'mesh_background.dart';

class FooterNav extends StatelessWidget {
  final String active;
  final Function(String) onTabChange;

  const FooterNav({
    super.key,
    required this.active,
    required this.onTabChange,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final themeManager = context.watch<ThemeManager>();

    return Container(
      width: 220,
      decoration: BoxDecoration(
        border: Border(
          right: BorderSide(
            color: scheme.onSurface.withOpacity(0.08),
          ),
        ),
      ),
      child: MeshBackground(
        blobs: themeManager.meshBlobs,
        base: theme.cardColor,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const SizedBox(height: 12),
            _NavItem(
              icon: Icons.home_rounded,
              label: 'Home',
              tag: 'home',
              active: active,
              onTap: onTabChange,
            ),
            _NavItem(
              icon: Icons.search_rounded,
              label: 'scan',
              tag: 'scan',
              active: active,
              onTap: onTabChange,
            ),
            _NavItem(
              icon: Icons.receipt_long_rounded,
              label: 'Realtime Logs',
              tag: 'rtp',
              active: active,
              onTap: onTabChange,
            ),
            _NavItem(
              icon: Icons.shield_outlined,
              label: 'Quarantine',
              tag: 'quarantine',
              active: active,
              onTap: onTabChange,
            ),
            _NavItem(
              icon: Icons.settings_outlined,
              label: 'Settings',
              tag: 'settings',
              active: active,
              onTap: onTabChange,
            ),
          ],
        ),
      ),
    );
  }
}

class _NavItem extends StatelessWidget {
  final IconData icon;
  final String label;
  final String tag;
  final String active;
  final Function(String) onTap;

  const _NavItem({
    required this.icon,
    required this.label,
    required this.tag,
    required this.active,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final text = theme.textTheme;

    final bool isActive = active == tag;

    final Color fg = isActive
        ? scheme.primary
        : scheme.onSurface.withOpacity(0.75);

    final Color bg = isActive
        ? scheme.primary.withOpacity(0.18)
        : Colors.transparent;

    return InkWell(
      onTap: () => onTap(tag),
      child: Container(
        margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
        decoration: BoxDecoration(
          color: bg,
          borderRadius: BorderRadius.circular(10),
        ),
        child: Row(
          children: [
            Icon(icon, size: 22, color: fg),
            const SizedBox(width: 14),
            Text(
              label,
              style: text.bodyMedium?.copyWith(
                color: fg,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }
}