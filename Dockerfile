# 基础镜像
FROM python:3.12-slim

# 设置工作目录
WORKDIR /app

# 复制依赖文件
COPY requirements.txt ./

# 安装依赖
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# 复制项目代码
COPY src ./src
COPY README.md ./
COPY img.png ./

# 设置环境变量（可选）
ENV PYTHONUNBUFFERED=1

# 暴露端口
EXPOSE 54321

# 启动命令
CMD ["python", "src/eodo/app.py", "-p", "54321"]