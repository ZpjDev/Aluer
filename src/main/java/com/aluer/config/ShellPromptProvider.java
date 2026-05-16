package com.aluer.config;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.shell.jline.PromptProvider;
import org.springframework.stereotype.Component;
import org.jline.utils.AttributedString;
import org.jline.utils.AttributedStyle;

/**
 * Aluer Shell 自定义提示符 — 美观的 ANSI 彩色 Prompt
 *
 * 使用 JLine AttributedStyle 实现彩色终端输出，
 * 显示当前运行模式和项目标识。
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class ShellPromptProvider implements PromptProvider {

    /** ANSI 前景色 */
    private static final int GOLD = 220;
    private static final int CYAN = 51;
    private static final int GRAY = 245;
    private static final int WHITE = 255;

    @Override
    public AttributedString getPrompt() {
        AttributedStyle goldStyle = AttributedStyle.DEFAULT.foreground(GOLD).bold();
        AttributedStyle cyanStyle = AttributedStyle.DEFAULT.foreground(CYAN);
        AttributedStyle grayStyle = AttributedStyle.DEFAULT.foreground(GRAY);
        AttributedStyle whiteStyle = AttributedStyle.DEFAULT.foreground(WHITE);

        return AttributedString.join(
            AttributedString.EMPTY,
            new AttributedString("╭─", grayStyle),
            new AttributedString("Aluer", goldStyle),
            new AttributedString("·", grayStyle),
            new AttributedString("ServerGuard", cyanStyle),
            new AttributedString("\n╰─", grayStyle),
            new AttributedString("> ", whiteStyle)
        );
    }
}
