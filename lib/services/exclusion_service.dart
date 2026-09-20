import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import 'rtp_service.dart';

class ExclusionService {
  static const _key = 'cs_exclusions_v1';

  List<String> folders = [];
  List<String> shas = [];

  Future<void> load() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_key);

    if (raw == null || raw.isEmpty) {
      folders = [];
      shas = [];
      return;
    }

    try {
      final decoded = jsonDecode(raw) as Map<String, dynamic>;
      final f = decoded['folders'] as List<dynamic>? ?? [];
      final s = decoded['shas'] as List<dynamic>? ?? [];

      folders = f.map((e) => e.toString()).toList();
      shas = s.map((e) => e.toString()).toList();
    } catch (_) {
      folders = [];
      shas = [];
    }
  }

  Future<void> save() async {
    final prefs = await SharedPreferences.getInstance();
    final data = <String, dynamic>{
      'folders': folders,
      'shas': shas,
    };
    await prefs.setString(_key, jsonEncode(data));
  }

  Future<bool> addFolder(String path) async {
    if (folders.contains(path)) return true;
    if (await RtpService.isInstalled() && !await RtpService.addExclusion('--exclude-folder', path)) {
      return false;
    }
    folders.add(path);
    await save();
    return true;
  }

  Future<bool> addSha(String sha) async {
    if (shas.contains(sha)) return true;
    if (await RtpService.isInstalled() && !await RtpService.addExclusion('--exclude-sha', sha)) {
      return false;
    }
    shas.add(sha);
    await save();
    return true;
  }

  bool skipFolder(String filePath) {
    for (final f in folders) {
      if (filePath.startsWith(f)) return true;
    }
    return false;
  }

  bool skipSha(String sha) {
    return shas.contains(sha);
  }
}
