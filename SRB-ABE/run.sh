#!/bin/bash
lengths=(5 10 15 20 25 30 35 40 45 50) #

# 创建带时间戳的目录
output_dir="./output/$(date +'%Y-%m-%d_%H-%M-%S')"
mkdir -p "$output_dir" || { echo "目录创建失败"; exit 1; }

for length in "${lengths[@]}"; do
    # 定义文件路径（目录+length.txt ）
    output_file="${output_dir}/${length}.txt"

    g++ -std=c++17 -o test test.cpp  ./detail/*.cpp  -lpbc -lgmp -fopenmp

    # 运行程序并记录输出
    echo "===== 开始处理 length = ${length} =====" | tee -a "$output_file"
    ./test "$length" | tee -a "$output_file"
    echo -e "[完成] 结果已保存至 ${output_file}\n" | tee -a "$output_file"
done