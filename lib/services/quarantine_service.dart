import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:path/path.dart' as p;
import '../utils/exclusions_store.dart';

class QuarantineService {
  static Directory? _sharedDir;

  static Future<void> init() async {
    if (_sharedDir != null) return;

    final programData = Platform.environment['ProgramData'] ?? r'C:\ProgramData';
    _sharedDir = Directory(p.join(programData, 'ColourSwift', 'AvarionX', 'Quarantine'));
    if (!await _sharedDir!.exists()) {
      await _sharedDir!.create(recursive: true);
    }
    try {
      await ExclusionsStore.instance.init();
    } catch (_) {}
  }

  static String _id() {
    final r = Random.secure();
    final a = r.nextInt(1 << 32);
    final b = r.nextInt(1 << 32);
    final c = DateTime.now().millisecondsSinceEpoch;
    return '${c.toRadixString(16)}_${a.toRadixString(16)}_${b.toRadixString(16)}';
  }

  static Future<Map<String, dynamic>> quarantineFile(
      String srcPath, {
        String? label,
        double? confidence,
      }) async {
    await init();

    final f = File(srcPath);
    if (!await f.exists()) {
      throw Exception('Source not found');
    }

    final id = _id();
    final qPath = p.join(_sharedDir!.path, id);
    await f.copy(qPath);

    final meta = <String, dynamic>{
      'id': id,
      'qPath': qPath,
      'name': p.basename(srcPath),
      'originalPath': srcPath,
      'originalExt': p.extension(srcPath),
      'size': await File(qPath).length(),
      'date': DateTime.now().toIso8601String(),
      if (label != null) 'label': label,
      if (confidence != null) 'confidence': confidence,
    };

    await File(p.join(_sharedDir!.path, '$id.json'))
        .writeAsString(jsonEncode(meta), flush: true);

    try {
      await f.delete();
      if (await f.exists()) {
        meta['deleteFailed'] = true;
      }
    } catch (_) {
      meta['deleteFailed'] = true;
    }

    return meta;
  }

  static Future<String> restore(String id) async {
    await init();

    final metaFile = File(p.join(_sharedDir!.path, '$id.json'));
    if (!await metaFile.exists()) {
      throw Exception('Quarantine metadata missing');
    }
    final meta = Map<String, dynamic>.from(jsonDecode(await metaFile.readAsString()));
    final qFile = File(meta['qPath'] as String);
    if (!await qFile.exists()) {
      throw Exception('Quarantine file missing');
    }

    final orig = meta['originalPath'] as String;
    final parent = Directory(p.dirname(orig));
    if (!await parent.exists()) {
      await parent.create(recursive: true);
    }

    var outPath = orig;
    if (await File(outPath).exists()) {
      final dir = p.dirname(orig);
      final base = p.basenameWithoutExtension(orig);
      final ext = p.extension(orig);
      outPath = p.join(dir, '${base}_restored$ext');
    }

    await qFile.copy(outPath);
    await qFile.delete();
    await metaFile.delete();

    try {
      await ExclusionsStore.instance.addTemporary(
        outPath,
        const Duration(hours: 24),
      );
    } catch (_) {}

    return outPath;
  }

  static Future<String?> shaFor(Map<String, dynamic> meta) async {
    final q = meta['qPath'];
    if (q is! String) return null;
    final f = File(q);
    if (!await f.exists()) return null;
    try {
      return (await sha256.bind(f.openRead()).first).toString();
    } catch (_) {
      return null;
    }
  }

  static Future<void> deleteForever(String id) async {
    await init();

    final metaFile = File(p.join(_sharedDir!.path, '$id.json'));
    if (await metaFile.exists()) {
      final meta = Map<String, dynamic>.from(jsonDecode(await metaFile.readAsString()));
      final qFile = File(meta['qPath'] as String);
      if (await qFile.exists()) {
        await qFile.delete();
      }
      await metaFile.delete();
    }
  }

  static Future<List<Map<String, dynamic>>> listAll() async {
    await init();

    final out = <Map<String, dynamic>>[];
    await for (final entity in _sharedDir!.list()) {
      if (entity is! File) continue;
      final name = p.basename(entity.path).toLowerCase();
      if (!name.endsWith('.json') || name == 'exclusions.json') continue;
      try {
        final decoded = jsonDecode(await entity.readAsString());
        if (decoded is! Map) continue;
        final meta = Map<String, dynamic>.from(decoded);
        if (meta['id'] is! String || meta['qPath'] is! String) continue;
        if (DateTime.tryParse('${meta['date']}') == null) continue;
        meta['size'] = meta['size'] is num ? (meta['size'] as num).toInt() : 0;
        out.add(meta);
      } catch (_) {}
    }

    out.sort(
          (a, b) => DateTime.parse(b['date'])
          .compareTo(DateTime.parse(a['date'])),
    );

    return out;
  }

  static Future<int> totalSize() async {
    await init();
    final list = await listAll();
    return list.fold<int>(0, (s, e) => s + (e['size'] as int));
  }

  static Future<void> purgeOlderThan(Duration age) async {
    await init();

    final now = DateTime.now();
    final list = await listAll();

    for (final m in list) {
      final t = DateTime.parse(m['date']);
      if (now.difference(t) > age) {
        await deleteForever(m['id']);
      }
    }
  }

  static Future<List<String>> restoreManyIsolated(
      Iterable<String> ids,
      ) async {
    await init();

    final outPaths = <String>[];
    for (final id in ids) {
      try {
        outPaths.add(await restore(id));
      } catch (_) {}
    }
    return outPaths;
  }
}