import 'package:flutter/material.dart';
import 'tokens.dart';

enum VpTone { neutral, success, warning, danger, info }

class VpNotice extends StatelessWidget {
  const VpNotice({
    super.key,
    required this.title,
    required this.message,
    this.tone = VpTone.neutral,
    this.action,
    this.live = false,
  });
  final String title;
  final String message;
  final VpTone tone;
  final Widget? action;
  final bool live;
  @override
  Widget build(BuildContext context) {
    final c = VpColors.of(context);
    final (fg, bg, icon) = switch (tone) {
      VpTone.success => (
        c.success,
        c.successSurface,
        Icons.check_circle_outline,
      ),
      VpTone.warning => (
        c.warning,
        c.warningSurface,
        Icons.warning_amber_rounded,
      ),
      VpTone.danger => (c.danger, c.dangerSurface, Icons.error_outline),
      VpTone.info => (c.info, c.infoSurface, Icons.info_outline),
      VpTone.neutral => (c.textSecondary, c.surfaceSubtle, Icons.info_outline),
    };
    return Semantics(
      liveRegion: live,
      container: true,
      child: Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: bg,
          borderRadius: BorderRadius.circular(10),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            ExcludeSemantics(child: Icon(icon, color: fg, size: 22)),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: Theme.of(context).textTheme.titleSmall?.copyWith(
                      color: fg,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    message,
                    style: Theme.of(
                      context,
                    ).textTheme.bodySmall?.copyWith(color: fg),
                  ),
                  if (action != null) ...[const SizedBox(height: 8), action!],
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class VpPanel extends StatelessWidget {
  const VpPanel({
    super.key,
    required this.child,
    this.padding = const EdgeInsets.all(24),
  });
  final Widget child;
  final EdgeInsetsGeometry padding;
  @override
  Widget build(BuildContext context) {
    final c = VpColors.of(context);
    return Container(
      padding: padding,
      decoration: BoxDecoration(
        color: c.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: MediaQuery.highContrastOf(context)
              ? c.borderControl
              : c.borderSubtle,
        ),
      ),
      child: child,
    );
  }
}

class VpPage extends StatelessWidget {
  const VpPage({
    super.key,
    required this.eyebrow,
    required this.title,
    required this.description,
    required this.children,
    this.action,
    this.maxWidth = 1280,
  });
  final String eyebrow, title, description;
  final List<Widget> children;
  final Widget? action;
  final double maxWidth;
  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, box) {
      final margin = box.maxWidth < 360
          ? 16.0
          : box.maxWidth < 600
          ? 20.0
          : box.maxWidth < 960
          ? 24.0
          : 32.0;
      return SafeArea(
        child: Align(
          alignment: Alignment.topCenter,
          child: SingleChildScrollView(
            keyboardDismissBehavior: ScrollViewKeyboardDismissBehavior.onDrag,
            padding: EdgeInsets.all(margin),
            child: ConstrainedBox(
              constraints: BoxConstraints(maxWidth: maxWidth),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    eyebrow,
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: VpColors.of(context).textSecondary,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(title, style: Theme.of(context).textTheme.headlineLarge),
                  const SizedBox(height: 8),
                  ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 720),
                    child: Text(description),
                  ),
                  if (action != null) ...[const SizedBox(height: 20), action!],
                  const SizedBox(height: 32),
                  for (var i = 0; i < children.length; i++) ...[
                    children[i],
                    if (i < children.length - 1) const SizedBox(height: 24),
                  ],
                  const SizedBox(height: 24),
                ],
              ),
            ),
          ),
        ),
      );
    },
  );
}

class VpEmpty extends StatelessWidget {
  const VpEmpty({
    super.key,
    required this.title,
    required this.message,
    this.action,
  });
  final String title, message;
  final Widget? action;
  @override
  Widget build(BuildContext context) => VpPanel(
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Icon(
          Icons.inbox_outlined,
          color: VpColors.of(context).textSecondary,
          size: 28,
        ),
        const SizedBox(height: 16),
        Text(title, style: Theme.of(context).textTheme.titleLarge),
        const SizedBox(height: 8),
        Text(message),
        if (action != null) ...[const SizedBox(height: 20), action!],
      ],
    ),
  );
}

/// Static stage text remains when the OS requests reduced motion.
class VpLoading extends StatelessWidget {
  const VpLoading({super.key, this.label = '正在读取真实状态…'});
  final String label;
  @override
  Widget build(BuildContext context) => Semantics(
    liveRegion: true,
    child: Row(
      children: [
        if (MediaQuery.disableAnimationsOf(context))
          const Icon(Icons.hourglass_empty)
        else
          const SizedBox(
            width: 20,
            height: 20,
            child: CircularProgressIndicator(strokeWidth: 2),
          ),
        const SizedBox(width: 12),
        Expanded(child: Text(label)),
      ],
    ),
  );
}

class VpKeyValue extends StatelessWidget {
  const VpKeyValue(
    this.label,
    this.value, {
    super.key,
    this.selectable = false,
  });
  final String label, value;
  final bool selectable;
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 8),
    child: LayoutBuilder(
      builder: (context, constraints) {
        final labelWidget = Text(
          label,
          style: Theme.of(context).textTheme.bodySmall?.copyWith(
            color: VpColors.of(context).textSecondary,
          ),
        );
        final valueWidget = selectable ? SelectableText(value) : Text(value);
        if (constraints.maxWidth < 420 ||
            MediaQuery.textScalerOf(context).scale(16) > 24) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [labelWidget, const SizedBox(height: 4), valueWidget],
          );
        }
        return Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(width: 140, child: labelWidget),
            Expanded(child: valueWidget),
          ],
        );
      },
    ),
  );
}

class VpSection extends StatelessWidget {
  const VpSection({
    super.key,
    required this.title,
    required this.child,
    this.description,
  });
  final String title;
  final String? description;
  final Widget child;
  @override
  Widget build(BuildContext context) => VpPanel(
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(title, style: Theme.of(context).textTheme.titleLarge),
        if (description != null) ...[
          const SizedBox(height: 8),
          Text(description!),
        ],
        const SizedBox(height: 20),
        child,
      ],
    ),
  );
}
