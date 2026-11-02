import 'package:flutter/material.dart';

// Exact transcription of docs/design/vp-ui-tokens.json v0.1.
// Update source token data and this class together; no visual certification implied.
class VpColors extends ThemeExtension<VpColors> {
  const VpColors({
    required this.canvas,
    required this.surface,
    required this.surfaceSubtle,
    required this.textPrimary,
    required this.textSecondary,
    required this.textTertiary,
    required this.borderSubtle,
    required this.borderControl,
    required this.action,
    required this.onAction,
    required this.selectedSurface,
    required this.success,
    required this.successSurface,
    required this.warning,
    required this.warningSurface,
    required this.danger,
    required this.dangerSurface,
    required this.info,
    required this.infoSurface,
    required this.focus,
  });
  final Color canvas;
  final Color surface;
  final Color surfaceSubtle;
  final Color textPrimary;
  final Color textSecondary;
  final Color textTertiary;
  final Color borderSubtle;
  final Color borderControl;
  final Color action;
  final Color onAction;
  final Color selectedSurface;
  final Color success;
  final Color successSurface;
  final Color warning;
  final Color warningSurface;
  final Color danger;
  final Color dangerSurface;
  final Color info;
  final Color infoSurface;
  final Color focus;
  static const light = VpColors(
    canvas: Color(0xFFF5F6F3),
    surface: Color(0xFFFFFFFF),
    surfaceSubtle: Color(0xFFEEF1ED),
    textPrimary: Color(0xFF17211D),
    textSecondary: Color(0xFF53625A),
    textTertiary: Color(0xFF627068),
    borderSubtle: Color(0xFFD8DED8),
    borderControl: Color(0xFF7B8A80),
    action: Color(0xFF235B4B),
    onAction: Color(0xFFFFFFFF),
    selectedSurface: Color(0xFFE3EEE8),
    success: Color(0xFF206748),
    successSurface: Color(0xFFE6F2EA),
    warning: Color(0xFF855A13),
    warningSurface: Color(0xFFFFF2D6),
    danger: Color(0xFFA73735),
    dangerSurface: Color(0xFFFCECE8),
    info: Color(0xFF325D80),
    infoSurface: Color(0xFFE9F1F8),
    focus: Color(0xFF2769B3),
  );
  static const dark = VpColors(
    canvas: Color(0xFF101714),
    surface: Color(0xFF18211D),
    surfaceSubtle: Color(0xFF202D26),
    textPrimary: Color(0xFFEBF0EC),
    textSecondary: Color(0xFFB0BDB4),
    textTertiary: Color(0xFF98A89E),
    borderSubtle: Color(0xFF35453B),
    borderControl: Color(0xFF718679),
    action: Color(0xFF9BD4BC),
    onAction: Color(0xFF12281C),
    selectedSurface: Color(0xFF253F33),
    success: Color(0xFF93D7AE),
    successSurface: Color(0xFF203C2A),
    warning: Color(0xFFEBC47A),
    warningSurface: Color(0xFF3B301E),
    danger: Color(0xFFF1AAA1),
    dangerSurface: Color(0xFF402522),
    info: Color(0xFFA6C8E7),
    infoSurface: Color(0xFF213446),
    focus: Color(0xFF95BFF5),
  );
  @override
  VpColors copyWith({
    Color? canvas,
    Color? surface,
    Color? surfaceSubtle,
    Color? textPrimary,
    Color? textSecondary,
    Color? textTertiary,
    Color? borderSubtle,
    Color? borderControl,
    Color? action,
    Color? onAction,
    Color? selectedSurface,
    Color? success,
    Color? successSurface,
    Color? warning,
    Color? warningSurface,
    Color? danger,
    Color? dangerSurface,
    Color? info,
    Color? infoSurface,
    Color? focus,
  }) => VpColors(
    canvas: canvas ?? this.canvas,
    surface: surface ?? this.surface,
    surfaceSubtle: surfaceSubtle ?? this.surfaceSubtle,
    textPrimary: textPrimary ?? this.textPrimary,
    textSecondary: textSecondary ?? this.textSecondary,
    textTertiary: textTertiary ?? this.textTertiary,
    borderSubtle: borderSubtle ?? this.borderSubtle,
    borderControl: borderControl ?? this.borderControl,
    action: action ?? this.action,
    onAction: onAction ?? this.onAction,
    selectedSurface: selectedSurface ?? this.selectedSurface,
    success: success ?? this.success,
    successSurface: successSurface ?? this.successSurface,
    warning: warning ?? this.warning,
    warningSurface: warningSurface ?? this.warningSurface,
    danger: danger ?? this.danger,
    dangerSurface: dangerSurface ?? this.dangerSurface,
    info: info ?? this.info,
    infoSurface: infoSurface ?? this.infoSurface,
    focus: focus ?? this.focus,
  );
  @override
  VpColors lerp(covariant VpColors? other, double t) {
    if (other == null) return this;
    return VpColors(
      canvas: Color.lerp(canvas, other.canvas, t)!,
      surface: Color.lerp(surface, other.surface, t)!,
      surfaceSubtle: Color.lerp(surfaceSubtle, other.surfaceSubtle, t)!,
      textPrimary: Color.lerp(textPrimary, other.textPrimary, t)!,
      textSecondary: Color.lerp(textSecondary, other.textSecondary, t)!,
      textTertiary: Color.lerp(textTertiary, other.textTertiary, t)!,
      borderSubtle: Color.lerp(borderSubtle, other.borderSubtle, t)!,
      borderControl: Color.lerp(borderControl, other.borderControl, t)!,
      action: Color.lerp(action, other.action, t)!,
      onAction: Color.lerp(onAction, other.onAction, t)!,
      selectedSurface: Color.lerp(selectedSurface, other.selectedSurface, t)!,
      success: Color.lerp(success, other.success, t)!,
      successSurface: Color.lerp(successSurface, other.successSurface, t)!,
      warning: Color.lerp(warning, other.warning, t)!,
      warningSurface: Color.lerp(warningSurface, other.warningSurface, t)!,
      danger: Color.lerp(danger, other.danger, t)!,
      dangerSurface: Color.lerp(dangerSurface, other.dangerSurface, t)!,
      info: Color.lerp(info, other.info, t)!,
      infoSurface: Color.lerp(infoSurface, other.infoSurface, t)!,
      focus: Color.lerp(focus, other.focus, t)!,
    );
  }

  static VpColors of(BuildContext context) =>
      Theme.of(context).extension<VpColors>()!;
}
