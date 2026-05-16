# Aluer ServerGuard 开发规范

## 工作原则

1. **YOLO 模式** — 不等确认直接执行，不犹豫，不反复询问
2. **代码注释** — 每个方法、关键逻辑必须有详细中文注释，解释 WHY 而非 WHAT
3. **测试纪律** — 修改代码前后必须跑全量测试，278 项一个不能挂
4. **Token 不限** — 把能做出来的功能全部做出来，不节省 Token，永远不在意 Token 消耗
5. **文档严肃** — 专业正式语气，完全贴合项目实际代码，写之前核实，不编造
6. **频繁提交** — 每个有意义的改动单独提交 Git，不攒到最后一并提交
7. **Git 记录严肃** — 中文 commit message，正式规范，不用玩梗用语
8. **全盘 IDE 控制** — 可以直接读写、修改任何 IDE 配置和项目文件，保证人在 IDE 中能直观看到和测试所有代码
9. **并行 Agent 开发** — 面对多个独立任务时，创建多个并行 Agent 同时工作，最大化开发效率
10. **IDE 配置同步** — 每次完成代码改动后，如果改动影响 IDE 调试/运行/测试体验，必须同步更新 .idea/ 下的运行配置、模块配置等 IDE 文件，确保人打开 IDE 就能直接运行测试

## 测试规范

- **打靶试验** — 测试必须模拟真实 Minecraft 服务器环境，做本地打靶试验
- **生产对齐** — 测试数据和行为必须与实际生产环境对齐，不编造假数据，不简化跳过
- **不限资源** — 不在意本机性能消耗，可以随意启动进程、端口、模拟数据量
- **全部可运行** — 每一行代码都必须可编译、可运行、可验证，禁止伪代码、TODO 占位、空实现
- 双构造函数模式（无参 + @Autowired）用于测试兼容
- 内部静态结果类 + 静态工厂方法（clean/blocked/flagged 等）

## 技术规范

- Java 21，Spring Boot 3.2.0，Maven 3.9.6 (bundled)
- 编译：`./apache-maven-3.9.6/bin/mvn clean compile`（必须 clean，禁止增量编译）
- 测试：`./apache-maven-3.9.6/bin/mvn clean test`
- 打包：`./apache-maven-3.9.6/bin/mvn clean package -DskipTests`
- **禁止 IDE Make 增量编译** — 所有 IDE Run Configuration 必须配置 Maven.BeforeRunTask clean compile，确保每次运行从零编译
- PaperMC API 1.21.1-R0.1-SNAPSHOT（provided scope）
- Agent 通信：WebSocket（spring-boot-starter-websocket + java.net.http.WebSocket）
