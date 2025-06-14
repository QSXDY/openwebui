import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Any
import threading

from open_webui.models.subscription import DailyCreditGrants

logger = logging.getLogger(__name__)


class TaskScheduler:
    """任务调度器 - 处理定时任务（已移除每日积分发放）"""

    def __init__(self):
        self.running = False
        self.scheduler_thread = None

    def start(self):
        """启动任务调度器"""
        if not self.running:
            self.running = True
            self.scheduler_thread = threading.Thread(
                target=self._run_scheduler, daemon=True
            )
            self.scheduler_thread.start()
            logger.info("任务调度器已启动")

    def stop(self):
        """停止任务调度器"""
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join()
        logger.info("任务调度器已停止")

    def _run_scheduler(self):
        """运行调度器主循环"""
        last_expire_check_date = None

        while self.running:
            try:
                current_date = datetime.now().date()

                # 检查套餐过期（每天执行一次）
                if last_expire_check_date != current_date:
                    current_hour = datetime.now().hour
                    if current_hour >= 1:  # 凌晨1点后执行
                        logger.info(f"开始检查套餐过期 - {current_date}")
                        self._check_subscription_expiry()
                        last_expire_check_date = current_date
                        logger.info(f"套餐过期检查完成 - {current_date}")

                # 每小时检查一次
                time.sleep(3600)

            except Exception as e:
                logger.error(f"任务调度器运行错误: {str(e)}")
                time.sleep(300)  # 发生错误时等待5分钟后重试

    def _check_subscription_expiry(self) -> Dict[str, Any]:
        """检查套餐过期"""
        try:
            from open_webui.models.subscription import SubscriptionCredits

            result = SubscriptionCredits.check_and_expire_subscriptions()
            logger.info(f"套餐过期检查结果: {result}")
            return result
        except Exception as e:
            logger.error(f"套餐过期检查失败: {str(e)}")
            return {"success": False, "error": str(e)}

    # 移除每日积分发放相关方法
    # def _execute_daily_credit_grants(self):
    #     pass


# 全局任务调度器实例
task_scheduler = TaskScheduler()


def start_task_scheduler():
    """启动任务调度器"""
    task_scheduler.start()


def stop_task_scheduler():
    """停止任务调度器"""
    task_scheduler.stop()


def manual_execute_daily_grants() -> Dict[str, Any]:
    """手动执行每日积分发放"""
    return task_scheduler._execute_daily_credit_grants()
