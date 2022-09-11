#!/usr/bin/env python3
# coding=utf-8

# Author: $￥
# @Time: 2021/10/09 13:29

import threading
import os
import sys
import datetime
import psutil

interval = 1
ratios = []
lock = threading.Lock()

log_time = datetime.datetime.now().strftime("%y-%m-%d %H-%M-%S")
output_file_name = "top_ryu_uti %s.txt" % log_time


def write_utilization(pid):
    global ratios

    # cmd = "ps aux | grep ryu-manager | grep -v grep"

    try:
        cpu_percent = pid.cpu_percent()

        value = cpu_percent
        print(value)

        # res.split()的期望数据是

        lock.acquire()
        ratios.append(value)
        lock.release()
    except ValueError:
        print("error parsing value")
        return
    except IndexError:
        print("no ryu process working")
        ratios.append(0.0)
    except Exception:
        print("error")

    # 这里因为每1s获取一次，就不写Lock了
    inner_timer = threading.Timer(interval, write_utilization, args=(pid,))
    inner_timer.start()

    # 每10个时间单位，输出一次count 到 file 里
    lock.acquire()
    if len(ratios) == 10:
        with open(file=output_file_name, mode="a+") as f:
            f.write("\n".join([str(num) for num in ratios]))
            f.write("\n")
        ratios.clear()
    lock.release()


if __name__ == "__main__":
    cmd = "ps -ef | grep ryu-manager | grep -v grep | awk '{print $2}'"
    try:
        pid = int(os.popen(cmd).readlines()[0])
        print(pid)
    except Exception:
        print("no ryu pid")

    with open(file=output_file_name, mode="a+")as f:
        f.write(datetime.datetime.now().strftime("%y-%m-%d %H-%M-%S"))
        f.write("\n")

    pid = psutil.Process(pid)
    timer = threading.Timer(interval, write_utilization, args = (pid, ))

    timer.start()


