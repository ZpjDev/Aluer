# Aluer ServerGuard 开发规范

## 工作原则

1. **YOLO 模式** — 不等确认直接执行，不犹豫，不反复询问
2. **代码注释** — 每个方法、关键逻辑必须有详细中文注释，解释 WHY 而非 WHAT
3. **测试纪律** — 修改代码前后必须跑全量测试，114 项一个不能挂
4. **Token 不限** — 把能做出来的功能全部做出来，不节省 Token
5. **文档严肃** — 专业正式语气，完全贴合项目实际代码，写之前核实，不编造
6. **频繁提交** — 每个有意义的改动单独提交 Git，不攒到最后一并提交
7. **Git 记录严肃** — 中文 commit message，正式规范，不用玩梗用语

## 技术规范

- Java 17，Spring Boot 3.2.0，Maven 3.9.6 (bundled)
- 编译：`./apache-maven-3.9.6/bin/mvn compile`
- 测试：`./apache-maven-3.9.6/bin/mvn test`
- 打包：`./apache-maven-3.9.6/bin/mvn package -DskipTests`
- 双构造函数模式（无参 + @Autowired）用于测试兼容
- 内部静态结果类 + 静态工厂方法（clean/blocked/flagged 等）
