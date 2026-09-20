import 'dart:io';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';

class RtpService {
  static String get _exeDir => File(Platform.resolvedExecutable).parent.path;
  static String get _exePath => _join(_exeDir, 'axservice.exe');
  static String get _hashPath => _join(_exeDir, 'axservice.sha256');
  static String get _notifyExePath => _join(_exeDir, 'axnotify.exe');
  static String get _notifyHashPath => _join(_exeDir, 'axnotify.sha256');

  static Future<bool> isInstalled() async {
    if (!Platform.isWindows) return false;
    try {
      final r = await Process.run('sc', ['query', 'AxService'], runInShell: false);
      final out = (r.stdout ?? '').toString();
      return !out.toLowerCase().contains('does not exist');
    } catch (_) {
      return false;
    }
  }

  static Future<bool> isRunning() async {
    if (!Platform.isWindows) return false;
    try {
      final r = await Process.run('sc', ['query', 'AxService'], runInShell: false);
      final out = (r.stdout ?? '').toString();
      return out.contains('RUNNING');
    } catch (_) {
      return false;
    }
  }

  static Future<int> _elevatedExit(String args) async {
    final exe = _exePath.replaceAll("'", "''");
    final safeArgs = args.replaceAll("'", "''");
    final script =
        "try { \$p = Start-Process -FilePath '$exe' -ArgumentList '$safeArgs' "
        "-Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit \$p.ExitCode } "
        "catch { exit 1223 }";
    try {
      final r = await Process.run(
        'powershell',
        ['-NoProfile', '-Command', script],
        runInShell: false,
      );
      return r.exitCode;
    } catch (_) {
      return 1;
    }
  }

  static Future<bool> _elevatedRun(String args) async {
    return (await _elevatedExit(args)) == 0;
  }

  static Future<bool> addExclusion(String kind, String value) async {
    if (!File(_exePath).existsSync()) return false;
    final cleaned = value
        .trim()
        .replaceAll('"', '')
        .replaceAll(RegExp(r'[\\/]+$'), '');
    if (cleaned.isEmpty) return false;
    return _elevatedRun('$kind "$cleaned"');
  }

  static bool _exeDirWritable() {
    try {
      final probe = File(_join(_exeDir, '.axwrite'));
      probe.writeAsStringSync('');
      probe.deleteSync();
      return true;
    } catch (_) {
      return false;
    }
  }

  static Future<bool> _plainRun(String args) async {
    try {
      final r = await Process.run(_exePath, [args], runInShell: false);
      return r.exitCode == 0;
    } catch (_) {
      return false;
    }
  }

  static Future<void> _killNotifyIfRunning() async {
    try {
      await Process.run('taskkill', ['/IM', 'axnotify.exe', '/F'], runInShell: false);
    } catch (_) {}
  }

  static Future<bool> _waitUntilStopped({Duration timeout = const Duration(seconds: 15)}) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      if (!await isRunning()) return true;
      await Future.delayed(const Duration(milliseconds: 300));
    }
    return !await isRunning();
  }

  static Future<bool> _waitUntilRunning({Duration timeout = const Duration(seconds: 10)}) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      if (await isRunning()) return true;
      await Future.delayed(const Duration(milliseconds: 300));
    }
    return isRunning();
  }

  static Future<Uint8List> _bundledBytes() async {
    final data = await rootBundle.load('assets/axservice/axservice.exe');
    return data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes);
  }

  static Future<Uint8List> _bundledNotifyBytes() async {
    final data = await rootBundle.load('assets/axservice/axnotify.exe');
    return data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes);
  }

  static Future<bool> _needsUnpack(Uint8List bundled) async {
    final exeFile = File(_exePath);
    if (!exeFile.existsSync()) return true;

    final hashFile = File(_hashPath);
    if (!hashFile.existsSync()) return true;

    final storedHash = hashFile.readAsStringSync().trim();
    final bundledHash = sha256.convert(bundled).toString();
    return storedHash != bundledHash;
  }

  static Future<bool> _needsNotifyUnpack(Uint8List bundled) async {
    final exeFile = File(_notifyExePath);
    if (!exeFile.existsSync()) return true;

    final hashFile = File(_notifyHashPath);
    if (!hashFile.existsSync()) return true;

    final storedHash = hashFile.readAsStringSync().trim();
    final bundledHash = sha256.convert(bundled).toString();
    return storedHash != bundledHash;
  }

  static Future<void> _writeExe(Uint8List bytes) async {
    await File(_exePath).writeAsBytes(bytes, flush: true);
    final hash = sha256.convert(bytes).toString();
    await File(_hashPath).writeAsString(hash, flush: true);
  }

  static Future<void> _writeNotifyExe(Uint8List bytes) async {
    await _killNotifyIfRunning();
    await File(_notifyExePath).writeAsBytes(bytes, flush: true);
    final hash = sha256.convert(bytes).toString();
    await File(_notifyHashPath).writeAsString(hash, flush: true);
  }

  static Future<void> _launchNotifyDetached() async {
    try {
      await Process.start(_notifyExePath, [], mode: ProcessStartMode.detached);
    } catch (_) {}
  }

  static Future<void> ensureLatestExe() async {
    if (!_exeDirWritable()) return;
    final bundled = await _bundledBytes();
    final bundledNotify = await _bundledNotifyBytes();
    final needsUnpack = await _needsUnpack(bundled);
    final needsNotifyUnpack = await _needsNotifyUnpack(bundledNotify);
    if (!needsUnpack && !needsNotifyUnpack) return;

    final wasRunning = needsUnpack ? await isRunning() : false;
    if (wasRunning) {
      if (!await _elevatedRun('--stop')) return;
      await _waitUntilStopped();
    }

    try {
      if (needsUnpack) {
        await _writeExe(bundled);
      }
      if (needsNotifyUnpack) {
        await _writeNotifyExe(bundledNotify);
      }
    } finally {
      if (wasRunning) {
        await _plainRun('--start');
      } else if (needsNotifyUnpack) {
        await _launchNotifyDetached();
      }
    }
  }

  static Future<bool> enableProtection() async {
    try {
      await ensureLatestExe();
    } catch (_) {}

    if (!File(_exePath).existsSync()) {
      throw Exception('axservice.exe not found at $_exePath');
    }

    if (await isInstalled()) {
      if (await isRunning()) return true;
      final started = await _plainRun('--start');
      return started && await _waitUntilRunning();
    }

    final installed = await _elevatedRun('--install');
    return installed && await _waitUntilRunning();
  }

  static Future<bool> ensureSetup() async {
    if (!Platform.isWindows) return false;
    try {
      await ensureLatestExe();
    } catch (_) {}
    if (!File(_exePath).existsSync()) return false;
    if (await isInstalled()) return true;
    final installed = await _elevatedRun('--install');
    return installed && await _waitUntilRunning();
  }

  static Future<bool> disableProtection() async {
    if (!await isInstalled()) return true;
    if (!await isRunning()) return true;
    final stopped = await _elevatedRun('--stop');
    return stopped && await _waitUntilStopped();
  }

  static String _join(String a, String b) {
    final sep = Platform.pathSeparator;
    if (a.endsWith(sep)) return '$a$b';
    return '$a$sep$b';
  }
}