import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../core/antivirus_bridge.dart';
import 'definitions_service.dart';
import 'update_service.dart';

class DefsAutoUpdateService {
  static const _enabledKey = 'defs_auto_update_enabled';
  static const _lastCheckKey = 'defs_last_update_check';

  static const Duration checkInterval = Duration(hours: 6);

  static Future<bool> isEnabled() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getBool(_enabledKey) ?? false;
  }

  static Future<void> setEnabled(bool enabled) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_enabledKey, enabled);
  }

  static Future<void> maybeRun() async {
    final prefs = await SharedPreferences.getInstance();

    final enabled = prefs.getBool(_enabledKey) ?? false;
    if (!enabled) return;

    final now = DateTime.now().millisecondsSinceEpoch;
    final lastCheck = prefs.getInt(_lastCheckKey) ?? 0;

    if (now - lastCheck < checkInterval.inMilliseconds) return;

    await prefs.setInt(_lastCheckKey, now);

    final server = await UpdateService.checkServerVersion();
    if (server == null) {
      debugPrint('[DefsUpdate] Server version check failed');
      return;
    }

    final serverVersion = server['version']?.toString();
    if (serverVersion == null || serverVersion.isEmpty) {
      debugPrint('[DefsUpdate] Server version missing/invalid');
      return;
    }

    final localVersion = await DefinitionsService.getLocalVersion();

    debugPrint('[DefsUpdate] Auto-check: local=$localVersion server=$serverVersion');

    if (_isNewer(serverVersion, localVersion)) {
      debugPrint('[DefsUpdate] Update available, downloading...');

      final ok = await UpdateService.downloadDatabase(
        onProgress: (_) {},
      );

      if (!ok) {
        debugPrint('[DefsUpdate] Download failed');
        return;
      }

      await DefinitionsService.setLocalVersion(serverVersion);

      final defsPath = DefinitionsService.defsPath;

      try {
        final rc = AntivirusBridge().reload(defsPath);
        debugPrint('[DefsUpdate] Engine reload rc=$rc');
      } catch (e) {
        debugPrint('[DefsUpdate] Engine reload failed: $e');
      }

      try {
        AntivirusBridge().initNetIoc(defsPath);
      } catch (_) {}

      debugPrint(
        '[DefsUpdate] Database updated to v$serverVersion at ${DateTime.now().toIso8601String()}',
      );
    } else {
      debugPrint('[DefsUpdate] No update needed');
    }
  }

  static bool _isNewer(String a, String b) {
    final av = a.split('.').map((e) => int.tryParse(e) ?? 0).toList();
    final bv = b.split('.').map((e) => int.tryParse(e) ?? 0).toList();

    for (int i = 0; i < 3; i++) {
      final ai = i < av.length ? av[i] : 0;
      final bi = i < bv.length ? bv[i] : 0;
      if (ai > bi) return true;
      if (ai < bi) return false;
    }
    return false;
  }
}