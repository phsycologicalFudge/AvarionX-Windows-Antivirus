import 'dart:async';
import 'dart:isolate';
import '../core/antivirus_bridge.dart';
import '../services/definitions_service.dart';

class AvEngine {
  static Future<int>? _initFuture;
  static bool _initialized = false;

  static bool get isInitialized => _initialized;

  static void prewarm() {
    if (_initFuture != null) return;
    Future.delayed(const Duration(milliseconds: 400), () {
      ensureInitialized();
    });
  }

  static Future<int> ensureInitialized() {
    if (_initFuture != null) return _initFuture!;
    _initFuture = _init();
    return _initFuture!;
  }

  static Future<int> _init() async {
    try {
      await DefinitionsService.ensureDefinitions();
      final defsPath = await DefinitionsService.ensureDefsPath();

      final result = await _runRustInit(defsPath);

      _initialized = (result == 0);
      return result;
    } catch (_) {
      return -1;
    }
  }

  static Future<int> _runRustInit(String defsPath) async {
    final receivePort = ReceivePort();

    await Isolate.spawn<_InitMessage>(
      _rustInitEntry,
      _InitMessage(sendPort: receivePort.sendPort, defsPath: defsPath),
    );

    final result = await receivePort.first as int;
    receivePort.close();
    return result;
  }
}

class _InitMessage {
  final SendPort sendPort;
  final String defsPath;

  _InitMessage({
    required this.sendPort,
    required this.defsPath,
  });
}

void _rustInitEntry(_InitMessage msg) {
  try {
    final av = AntivirusBridge();
    final code = av.init(msg.defsPath);
    av.free();
    msg.sendPort.send(code);
  } catch (_) {
    msg.sendPort.send(-1);
  }
}