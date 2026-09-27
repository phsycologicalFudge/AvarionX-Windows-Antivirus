import 'dart:convert';
import 'dart:isolate';
import 'antivirus_bridge.dart';

typedef ScanEntryHandler = void Function(String path, String entry);
typedef ScanProgressHandler = void Function(int scanned);

class ScanLogListener {
  static Isolate? _iso;
  static ReceivePort? _receive;
  static ScanEntryHandler? _handler;
  static ScanProgressHandler? _progressHandler;
  static Future<void>? _starting;

  static Future<void> ensureStarted() {
    if (_iso != null) return Future.value();
    return _starting ??= _start();
  }

  static Future<void> _start() async {
    final receive = ReceivePort();
    _receive = receive;
    _iso = await Isolate.spawn(_entry, receive.sendPort);
    receive.listen((msg) {
      if (msg is! Map) return;
      if (msg['event'] == 'dir_progress' && msg['scanned'] is int) {
        _progressHandler?.call(msg['scanned'] as int);
      } else if (msg['path'] is String && msg['entry'] is String) {
        _handler?.call(msg['path'] as String, msg['entry'] as String);
      }
    });
  }

  static void setHandler(ScanEntryHandler? handler) {
    _handler = handler;
  }

  static void setProgressHandler(ScanProgressHandler? handler) {
    _progressHandler = handler;
  }

  @pragma('vm:entry-point')
  static void _entry(SendPort root) {
    try {
      AntivirusBridge(
        enableScanLogs: true,
        scanLogSink: (msg) {
          try {
            final decoded = jsonDecode(msg);
            if (decoded is Map && decoded['event'] == 'entry_progress') {
              final path = decoded['path'];
              final entry = decoded['entry'];
              if (path is String && entry is String) {
                root.send({'path': path, 'entry': entry});
              }
            } else if (decoded is Map && decoded['event'] == 'dir_progress') {
              final scanned = decoded['scanned'];
              if (scanned is int) {
                root.send({'event': 'dir_progress', 'scanned': scanned});
              }
            }
          } catch (_) {}
        },
      );
    } catch (_) {}
  }
}