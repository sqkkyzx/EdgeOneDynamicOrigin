import subprocess
import threading
import time
import schedule
import argparse
from eodo import task


def run_task():
    import uuid
    task_id = str(uuid.uuid4())
    try:
        task.logger.info(f"[{task_id}] 启动")
        task.main(task_id=task_id)
        task.logger.info(f"[{task_id}] 结束")
    except Exception as e:
        print(e)
        task.logger.error(f"[{task_id}] 异常")

def start_scheduler(interval_minutes):
    schedule.every(interval_minutes).minutes.do(run_task)
    while True:
        schedule.run_pending()
        time.sleep(1)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interval', type=int, default=15, help='定时间隔（分钟）')
    parser.add_argument('-p', '--port', type=int, default=54321, help='Web UI 端口')
    args = parser.parse_args()

    # 1. 启动调度线程，只留一份
    scheduler_thread = threading.Thread(target=start_scheduler, args=(args.interval,), daemon=True)
    scheduler_thread.start()

    # 2. 启动 Streamlit 子进程
    from eodo import webui
    webui_path = webui.__file__
    proc = subprocess.Popen([
        "streamlit", "run", webui_path,
        "--server.port", str(args.port),
        "--", f"--interval={args.interval}"
    ])
    try:
        proc.wait()
    except KeyboardInterrupt:
        print("收到中断信号，正在关闭 Streamlit 服务...")
        proc.terminate()
        # 如果需要强制:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

if __name__ == "__main__":
    main()
