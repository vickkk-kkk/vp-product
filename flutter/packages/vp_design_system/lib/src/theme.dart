import 'package:flutter/material.dart';
import 'tokens.dart';

abstract final class VpTheme {
  static ThemeData build(Brightness brightness, {bool highContrast = false}) {
    final c = brightness == Brightness.dark ? VpColors.dark : VpColors.light;
    final border = highContrast ? c.borderControl : c.borderSubtle;
    TextStyle type(double size, double height, FontWeight weight) => TextStyle(
      fontSize: size,
      height: height / size,
      fontWeight: weight,
      fontVariations: [FontVariation('wght', weight.value.toDouble())],
      color: c.textPrimary,
      letterSpacing: 0,
    );
    final scheme =
        ColorScheme.fromSeed(
          seedColor: c.action,
          brightness: brightness,
        ).copyWith(
          primary: c.action,
          onPrimary: c.onAction,
          surface: c.surface,
          onSurface: c.textPrimary,
          onSurfaceVariant: c.textSecondary,
          error: c.danger,
          onError: c.surface,
          outline: c.borderControl,
          outlineVariant: border,
          secondaryContainer: c.selectedSurface,
          onSecondaryContainer: c.textPrimary,
        );
    return ThemeData(
      useMaterial3: true,
      fontFamily: 'packages/vp_design_system/VpSans',
      brightness: brightness,
      colorScheme: scheme,
      scaffoldBackgroundColor: c.canvas,
      extensions: [c],
      splashFactory: NoSplash.splashFactory,
      visualDensity: VisualDensity.standard,
      materialTapTargetSize: MaterialTapTargetSize.padded,
      focusColor: c.focus.withValues(alpha: .15),
      textTheme: TextTheme(
        displayLarge: type(48, 56, FontWeight.w600),
        displayMedium: type(40, 48, FontWeight.w600),
        displaySmall: type(32, 40, FontWeight.w600),
        headlineLarge: type(28, 36, FontWeight.w600),
        headlineMedium: type(22, 30, FontWeight.w600),
        headlineSmall: type(20, 28, FontWeight.w600),
        titleLarge: type(18, 26, FontWeight.w600),
        titleMedium: type(16, 24, FontWeight.w500),
        titleSmall: type(14, 20, FontWeight.w500),
        bodyLarge: type(16, 24, FontWeight.w400),
        bodyMedium: type(15, 22, FontWeight.w400),
        bodySmall: type(14, 20, FontWeight.w400),
        labelLarge: type(14, 20, FontWeight.w600),
        labelMedium: type(12, 18, FontWeight.w500),
        labelSmall: type(12, 18, FontWeight.w500),
      ),
      appBarTheme: AppBarTheme(
        backgroundColor: c.canvas,
        foregroundColor: c.textPrimary,
        elevation: 0,
        scrolledUnderElevation: 0,
        centerTitle: false,
      ),
      dividerTheme: DividerThemeData(
        color: border,
        thickness: highContrast ? 2 : 1,
        space: 1,
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: c.surface,
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 16,
          vertical: 16,
        ),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: BorderSide(color: c.borderControl),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: BorderSide(color: c.borderControl),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: BorderSide(color: c.focus, width: 2),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: BorderSide(color: c.danger, width: 2),
        ),
        errorMaxLines: 5,
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: ButtonStyle(
          minimumSize: const WidgetStatePropertyAll(Size(48, 48)),
          padding: const WidgetStatePropertyAll(
            EdgeInsets.symmetric(horizontal: 20, vertical: 12),
          ),
          shape: WidgetStatePropertyAll(
            RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
          ),
          side: WidgetStateProperty.resolveWith(
            (states) => states.contains(WidgetState.focused)
                ? BorderSide(color: c.focus, width: 2)
                : BorderSide.none,
          ),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          minimumSize: const Size(48, 48),
          side: BorderSide(color: c.borderControl),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(10),
          ),
        ),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(minimumSize: const Size(48, 48)),
      ),
      iconButtonTheme: IconButtonThemeData(
        style: IconButton.styleFrom(minimumSize: const Size(48, 48)),
      ),
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: c.surface,
        indicatorColor: c.selectedSurface,
        labelBehavior: NavigationDestinationLabelBehavior.alwaysShow,
      ),
      navigationRailTheme: NavigationRailThemeData(
        backgroundColor: c.canvas,
        indicatorColor: c.selectedSurface,
        selectedIconTheme: IconThemeData(color: c.action),
      ),
    );
  }
}
