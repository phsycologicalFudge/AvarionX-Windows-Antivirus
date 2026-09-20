import 'dart:io';
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'definitions_service.dart';

class UpdateService {
  static const String versionUrl =
      'https://github.com/phsycologicalfudge/AVDatabase/releases/latest/download/version.json';
  static const String defsUrl =
      'https://github.com/phsycologicalfudge/AVDatabase/releases/latest/download/defs.cs';

  static Future<Map<String, dynamic>?> checkServerVersion() async {
    try {
      final response = await http.get(
        Uri.parse(versionUrl),
        headers: {
          'User-Agent': 'ColourSwiftAV/1.0 (Flutter; Windows)',
          'Accept': 'application/json',
        },
      );
      if (response.statusCode == 200) {
        return jsonDecode(response.body);
      }
    } catch (_) {}
    return null;
  }

  static Future<String> getLocalVersion() => DefinitionsService.getLocalVersion();

  static Future<void> setLocalVersion(String version) =>
      DefinitionsService.setLocalVersion(version);

  static Future<bool> hasLocalDatabaseFiles() async {
    return File(DefinitionsService.defsPath).exists();
  }

  static Future<Map<String, String>> getLocalPaths() async {
    return {
      'defsPath': DefinitionsService.defsPath,
    };
  }

  static Future<Map<String, dynamic>> ensureDatabaseReady({
    bool forceServerCheck = false,
  }) async {
    final hasFiles = await hasLocalDatabaseFiles();
    final localVersion = await getLocalVersion();

    if (hasFiles && localVersion != '0.0.0' && !forceServerCheck) {
      return {
        'checked': false,
        'downloaded': false,
        'hasFiles': hasFiles,
        'localVersion': localVersion,
        'remoteVersion': null,
      };
    }

    final remote = await checkServerVersion();
    final remoteVersion = (remote?['version'] ?? '0.0.0').toString();
    final needsDownload =
        !hasFiles || localVersion == '0.0.0' || localVersion != remoteVersion;

    if (!needsDownload) {
      return {
        'checked': true,
        'downloaded': false,
        'hasFiles': hasFiles,
        'localVersion': localVersion,
        'remoteVersion': remoteVersion,
      };
    }

    final ok = await downloadDatabase(onProgress: (_) {});

    if (!ok) {
      return {
        'checked': true,
        'downloaded': false,
        'hasFiles': hasFiles,
        'localVersion': localVersion,
        'remoteVersion': remoteVersion,
      };
    }

    if (remoteVersion != '0.0.0') {
      await setLocalVersion(remoteVersion);
    }

    return {
      'checked': true,
      'downloaded': true,
      'hasFiles': true,
      'localVersion': remoteVersion != '0.0.0' ? remoteVersion : localVersion,
      'remoteVersion': remoteVersion,
    };
  }

  static Future<bool> downloadDatabase({
    required void Function(double) onProgress,
  }) async {
    try {
      final defsPath = DefinitionsService.defsPath;
      final client = http.Client();

      final uri = Uri.parse('$defsUrl?t=${DateTime.now().millisecondsSinceEpoch}');
      final res = await client.get(uri);
      if (res.statusCode != 200) throw 'HTTP ${res.statusCode}';

      final bytes = res.bodyBytes;
      final file = File(defsPath);
      final sink = file.openWrite();
      final total = bytes.length;
      int written = 0;
      const chunkSize = 64 * 1024;

      while (written < total) {
        final end = (written + chunkSize).clamp(0, total);
        sink.add(bytes.sublist(written, end));
        written = end;
        onProgress(written / total);
        await Future.delayed(const Duration(milliseconds: 16));
      }

      await sink.close();
      onProgress(1.0);

      client.close();
      return true;
    } catch (_) {
      return false;
    }
  }
}