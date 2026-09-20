import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:path/path.dart' as p;

class DefinitionsService {
  static String get _baseDir => File(Platform.resolvedExecutable).parent.path;
  static String get defsPath => p.join(_baseDir, 'defs.cs');
  static String get _versionPath => p.join(_baseDir, 'defs_version.txt');

  static Future<void> ensureDefinitions() async {
    debugPrint('=== ensureDefinitions() started ===');

    try {
      final dir = Directory(_baseDir);
      if (!dir.existsSync()) dir.createSync(recursive: true);

      String localVersion = '0.0.0';
      final versionFile = File(_versionPath);
      if (versionFile.existsSync()) {
        localVersion = versionFile.readAsStringSync().trim();
      }
      debugPrint('Local defs version: $localVersion');

      String bundledVersion = '0.0.0';
      try {
        final jsonStr = await rootBundle.loadString('assets/defs/version.json');
        final decoded = json.decode(jsonStr);
        bundledVersion = decoded['version'] ?? '0.0.0';
      } catch (_) {
        debugPrint('No bundled version.json found, skipping.');
      }
      debugPrint('Bundled defs version: $bundledVersion');

      final defsFile = File(defsPath);
      final shouldUpdate = _isNewer(bundledVersion, localVersion);

      if (!defsFile.existsSync() || shouldUpdate) {
        debugPrint(shouldUpdate ? 'Updating definitions...' : 'Copying missing defs...');
        await _copyAsset('defs.cs', defsPath);
        await File(_versionPath).writeAsString(bundledVersion, flush: true);
        debugPrint('Definitions updated to v$bundledVersion');
      } else {
        debugPrint('Definitions up to date, no copy needed.');
      }

      if (!defsFile.existsSync()) {
        throw Exception('Missing defs.cs after copy.');
      }

      debugPrint('ensureDefinitions() finished successfully');
    } catch (e, st) {
      debugPrint('Error in ensureDefinitions: $e');
      debugPrint('Stack trace: $st');
    }
  }

  static Future<String> ensureDefsPath() async {
    final file = File(defsPath);
    if (!file.existsSync()) {
      await _copyAsset('defs.cs', defsPath);
    }
    return defsPath;
  }

  static Future<String> getLocalVersion() async {
    final file = File(_versionPath);
    if (file.existsSync()) {
      return file.readAsStringSync().trim();
    }
    return '0.0.0';
  }

  static Future<void> setLocalVersion(String version) async {
    await File(_versionPath).writeAsString(version, flush: true);
  }

  static Future<void> _copyAsset(String assetName, String destPath) async {
    final data = await rootBundle.load('assets/defs/$assetName');
    final bytes = data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes);
    await File(destPath).writeAsBytes(bytes, flush: true);
    debugPrint('$assetName copied successfully.');
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