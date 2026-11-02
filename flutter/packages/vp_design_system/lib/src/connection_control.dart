import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:flutter/physics.dart';
import 'tokens.dart';

/// Motion renders caller-owned state; it never advances a connection lifecycle.
/// The short arc is indeterminate, not a percentage. Idle has no running ticker.
class VpConnectionControl extends StatefulWidget {
  const VpConnectionControl({
    super.key,
    required this.label,
    required this.onPressed,
    this.verified = false,
    this.busy = false,
    this.waitingForPermission = false,
    this.attention = false,
    this.compact = false,
    this.icon = Icons.power_settings_new_rounded,
  });
  final String label;
  final VoidCallback? onPressed;
  final bool verified, busy, waitingForPermission, attention, compact;
  final IconData icon;
  @override
  State<VpConnectionControl> createState() => _VpConnectionControlState();
}

class _VpConnectionControlState extends State<VpConnectionControl>
    with TickerProviderStateMixin {
  late final AnimationController _press = AnimationController.unbounded(
    vsync: this,
    value: 1,
  );
  late final AnimationController _orbit = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 1800),
  );
  bool _reduced = false;
  bool _visible = true;
  bool _focused = false;
  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _reduced = MediaQuery.disableAnimationsOf(context);
    _visible = TickerMode.of(context);
    _syncMotion();
  }

  @override
  void didUpdateWidget(VpConnectionControl oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.onPressed != null && widget.onPressed == null) _release();
    _syncMotion();
  }

  void _syncMotion() {
    if (_reduced || !_visible) {
      _press.stop();
      _press.value = 1;
      _orbit.stop();
      _orbit.value = 0;
    } else if (widget.busy && !widget.waitingForPermission) {
      if (!_orbit.isAnimating) _orbit.repeat();
    } else {
      _orbit.stop();
      _orbit.value = 0;
    }
  }

  void _down(TapDownDetails _) {
    if (_reduced || widget.onPressed == null) return;
    _press.animateTo(
      .965,
      duration: const Duration(milliseconds: 90),
      curve: Curves.easeOutCubic,
    );
  }

  void _release() {
    if (_reduced || !_visible) {
      _press.stop();
      _press.value = 1;
      return;
    }
    if ((_press.value - 1).abs() < .0001) return;
    _press.animateWith(
      SpringSimulation(
        const SpringDescription(mass: 1, stiffness: 420, damping: 30),
        _press.value,
        1,
        0,
      ),
    );
  }

  @override
  void dispose() {
    _press.dispose();
    _orbit.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final c = VpColors.of(context);
    final diameter = widget.compact ? 152.0 : 176.0;
    final enabled = widget.onPressed != null;
    final fill = widget.verified
        ? c.selectedSurface
        : enabled
        ? c.textPrimary
        : c.surfaceSubtle;
    final ink = widget.verified
        ? c.action
        : enabled
        ? c.canvas
        : c.textTertiary;
    final rim = _focused
        ? c.focus
        : widget.attention
        ? c.warning
        : widget.verified
        ? c.action
        : c.borderSubtle;
    final pending = widget.busy || widget.waitingForPermission;
    final duration = _reduced
        ? Duration.zero
        : const Duration(milliseconds: 220);
    return Semantics(
      button: true,
      enabled: enabled,
      label: widget.label,
      onTap: widget.onPressed,
      child: ExcludeSemantics(
        child: ScaleTransition(
          scale: _press,
          child: SizedBox(
            width: diameter + 36,
            height: diameter + 36,
            child: Stack(
              alignment: Alignment.center,
              children: [
                Positioned.fill(
                  child: AnimatedContainer(
                    duration: duration,
                    curve: Curves.easeOutCubic,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      border: Border.all(color: rim, width: _focused ? 2 : 1),
                    ),
                  ),
                ),
                Positioned.fill(
                  child: AnimatedOpacity(
                    opacity: pending ? 1 : 0,
                    duration: duration,
                    child: AnimatedBuilder(
                      animation: _orbit,
                      builder: (context, _) => CustomPaint(
                        painter: _PendingArc(
                          color: widget.attention ? c.warning : c.action,
                          rotation: _orbit.value,
                        ),
                      ),
                    ),
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.all(17),
                  child: AnimatedContainer(
                    duration: duration,
                    curve: Curves.easeOutCubic,
                    decoration: ShapeDecoration(
                      color: fill,
                      shape: CircleBorder(side: BorderSide(color: rim)),
                    ),
                    child: Material(
                      color: Colors.transparent,
                      shape: const CircleBorder(),
                      child: InkWell(
                        onTap: widget.onPressed,
                        onFocusChange: (value) =>
                            setState(() => _focused = value),
                        onTapDown: _down,
                        onTapUp: (_) => _release(),
                        onTapCancel: _release,
                        customBorder: const CircleBorder(),
                        focusColor: c.focus.withValues(alpha: .18),
                        hoverColor: ink.withValues(alpha: .06),
                        child: Center(
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Icon(
                                widget.waitingForPermission
                                    ? Icons.lock_outline_rounded
                                    : widget.icon,
                                size: widget.compact ? 38 : 44,
                                color: ink,
                              ),
                              const SizedBox(height: 12),
                              AnimatedSwitcher(
                                duration: _reduced
                                    ? Duration.zero
                                    : const Duration(milliseconds: 160),
                                switchInCurve: Curves.easeOut,
                                switchOutCurve: Curves.easeIn,
                                child: Text(
                                  widget.label,
                                  key: ValueKey(widget.label),
                                  textAlign: TextAlign.center,
                                  style: Theme.of(
                                    context,
                                  ).textTheme.labelLarge?.copyWith(color: ink),
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _PendingArc extends CustomPainter {
  const _PendingArc({required this.color, required this.rotation});
  final Color color;
  final double rotation;
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = color
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2
      ..strokeCap = StrokeCap.round;
    canvas.drawArc(
      Rect.fromCircle(
        center: size.center(Offset.zero),
        radius: size.width / 2 - 1,
      ),
      rotation * math.pi * 2 - math.pi / 2,
      math.pi / 3,
      false,
      paint,
    );
  }

  @override
  bool shouldRepaint(_PendingArc oldDelegate) =>
      oldDelegate.color != color || oldDelegate.rotation != rotation;
}
