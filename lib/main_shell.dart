import 'package:avarionx_desktop/rtp_logs.dart';
import 'package:avarionx_desktop/widgets/footer_nav.dart';
import 'package:flutter/material.dart';
import 'home_screen.dart';
import 'scan_screen.dart';
import 'quarantine/quarantine_screen.dart';
import 'settings_screen.dart';

class MainShell extends StatefulWidget {
  const MainShell({super.key});

  @override
  State<MainShell> createState() => _MainShellState();
}

class _MainShellState extends State<MainShell> {
  String _active = 'home';
  Key _homeKey = UniqueKey();
  Key _rtpKey = UniqueKey();
  Key _quarantineKey = UniqueKey();

  int get _index {
    switch (_active) {
      case 'quarantine':
        return 1;
      case 'rtp':
        return 2;
      case 'settings':
        return 3;
      case 'home':
      default:
        return 0;
    }
  }

  void _handleNavigate(String tab) {
    if (tab == 'scan') {
      showScanDialog(
        context,
        onOpenQuarantine: () => _handleNavigate('quarantine'),
      );
      return;
    }

    setState(() {
      _active = tab;
      if (tab == 'home') _homeKey = UniqueKey();
      if (tab == 'quarantine') _quarantineKey = UniqueKey();
      if (tab == 'rtp') _rtpKey = UniqueKey();
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Column(
        children: [
          Container(
            height: 1,
            color: Theme.of(context).colorScheme.onSurface.withOpacity(0.12),
          ),
          Expanded(
            child: Row(
              children: [
                FooterNav(
                  active: _active,
                  onTabChange: (tab) => _handleNavigate(tab),
                ),
                Expanded(
                  child: IndexedStack(
                    index: _index,
                    children: [
                      AvHomeScreen(
                        key: _homeKey,
                        visible: _active == 'home',
                        onNavigate: _handleNavigate,
                      ),
                      QuarantineScreen(key: _quarantineKey),
                      RtpLogsScreen(key: _rtpKey),
                      const SettingsScreen(),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}