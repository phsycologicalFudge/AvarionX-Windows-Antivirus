import 'dart:async';
import 'package:flutter/foundation.dart';
import 'defs_auto_update_service.dart';

class DefsUpdateScheduler {
  static Timer? _timer;

  static Future<void> enable() async {
    await DefsAutoUpdateService.setEnabled(true);
    _startTimer();
    DefsAutoUpdateService.maybeRun();
  }

  static Future<void> disable() async {
    await DefsAutoUpdateService.setEnabled(false);
    _timer?.cancel();
    _timer = null;
  }

  static void _startTimer() {
    _timer?.cancel();
    _timer = Timer.periodic(
      DefsAutoUpdateService.checkInterval,
          (_) async {
        debugPrint('[DefsScheduler] Periodic check triggered');
        await DefsAutoUpdateService.maybeRun();
      },
    );
  }

  static void resumeIfEnabled() async {
    final enabled = await DefsAutoUpdateService.isEnabled();
    if (enabled && _timer == null) {
      _startTimer();
      DefsAutoUpdateService.maybeRun();
    }
  }

  static void dispose() {
    _timer?.cancel();
    _timer = null;
  }
}