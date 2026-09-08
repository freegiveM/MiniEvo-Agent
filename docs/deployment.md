# 生产部署

```powershell
Copy-Item .env.example .env
docker compose up --build
```

Compose 会启动 Redis 和 EvoAgent。两个后端的退化行为**不一样**，这是刻意的：

- 不配 `EVOAGENT_REDIS_URL`：退回进程内线程队列（同样有 ACK、租约、
  指数退避与死信队列，只是不跨进程），适合本地演示
- 配了 `EVOAGENT_DATABASE_URL` 指向 PostgreSQL：直接抛 `NotImplementedError`

区别在于**静默降级会不会骗人**。队列退回内存后语义仍然成立，跑起来的东西
和你以为的一样；而存储退回 SQLite 时，你以为数据进了 Postgres，实际写在本地
文件里——同一个"自动退回"，一个安全，一个是事故。所以后者宁可起不来。

