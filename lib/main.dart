import 'dart:async';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:window_manager/window_manager.dart';
import 'boot_screen.dart';
import 'home_screen.dart';
import 'services/rtp_service.dart';
import 'services/theme_manager.dart';

const Size kWindowSize = Size(1200, 650);

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await windowManager.ensureInitialized();

  WindowOptions windowOptions = const WindowOptions(
    size: kWindowSize,
    minimumSize: kWindowSize,
    maximumSize: kWindowSize,
    center: true,
    titleBarStyle: TitleBarStyle.normal,
  );
  windowManager.waitUntilReadyToShow(windowOptions, () async {
    await windowManager.setResizable(false);
    await windowManager.setMaximizable(false);
    await windowManager.show();
    await windowManager.focus();
  });

  final themeManager = ThemeManager();
  await themeManager.init();

  runApp(
    ChangeNotifierProvider(
      create: (_) => themeManager,
      child: const MyApp(),
    ),
  );

  unawaited(RtpService.ensureSetup());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    final themeManager = Provider.of<ThemeManager>(context);

    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'AvarionX Antivirus',
      theme: themeManager.themeData,
      themeMode: themeManager.themeMode,
      home: const BootScreen(),
    );
  }
}