# GRANT: TEE-Aided Revocable Fine-Grained Access Control for IoT Environments

### Introduction

访问控制领域，涵盖了论文 [SRB-ABE](https://ieeexplore.ieee.org/abstract/document/9540689)、[HR-ABE](https://ieeexplore.ieee.org/abstract/document/10646706)、[EPF2DS](https://ieeexplore.ieee.org/abstract/document/10607924) 和 GRANT 的实现。

### Features

- Fine-Grained Bilateral Access Control（双边访问控制）

- Fully Policy-hidden（完全策略隐藏）

- Indirect User Revocation（用户间接撤销）

- Partial Outsourced Decryption（外包解密）

- TEE-Based Trust Verification（基于TEE的可信验证）


### :memo: 文件概览

- #### **GRANT (ours)**

    - `C++_version`: 
    - `SGX_version`: 

- #### **EPF2DS**

    - `C++_version`: only this version.

- #### **HR-ABE**

    - `SGX_version`: only this version.

- #### **SRB-ABE**

    - `C++_version`: only this version.


### 核心算法测试案例

#### 一、属性向量化测试

```C++
vector <string> alice_Attribute = {"+", "-", "+", "-", "+", "+", "+", "-", "+", "-"};  // 数据所有者属性集
vector <string> bob_Attribute = {"-", "+", "-", "+", "-", "+", "+", "-", "+", "-"};  // 数据请求者属性集
vector <string> alice_Policy = {"-", "+", "*", "*", "-", "*", "*", "-", "+", "-"};  // 数据所有者定义的访问策略
vector <string> bob_Policy = {"+", "-", "*", "-", "+", "+", "*", "-", "*", "-"};  // 数据请求者定义的访问策略

vector<int> u_alice = vectorize_Attribute(alice_Attribute);
vector<int> u_bob = vectorize_Attribute(bob_Attribute);
vector<int> v_alice = vectorize_Policy(alice_Policy);
vector<int> v_bob = vectorize_Policy(bob_Policy);

cout << "[Attribute vector] u_alice = [ ";
for (int val: u_alice) cout << val << " ";
cout << "]\n";

cout << "[Attribute vector] u_bob = [ ";
for (int val: u_bob) cout << val << " ";
cout << "]\n";

cout << "[Access vector] v_alice = [ ";
for (int val: v_alice) cout << val << " ";
cout << "]\n";

cout << "[Access vector] v_bob = [ ";
for (int val: v_bob) cout << val << " ";
cout << "]\n";

cout << "--- Inner product of (u_bob,v_alice): " << dotProduct(u_bob, v_alice) << '\n';
cout << "--- Inner product of (u_alice,v_bob): " << dotProduct(u_alice, v_bob) << '\n';
```

```shell
[Attribute vector] u_alice = [ 6 31 201 1441 10965 -1 ]
[Attribute vector] u_bob = [ 5 28 186 1360 10530 -1 ]
[Access vector] v_alice = [ 504 -450 145 -20 1 220 ]
[Access vector] v_bob = [ -189 111 -19 1 0 -71 ]
--- Inner product of (u_bob,v_alice): 0
--- Inner product of (u_alice,v_bob): 0
```



#### 二、时间编码测试
```C++
int bit_length = 4;

// 示例1: t=5 (0101)
auto [root1, V1] = TEalgorithm(5, bit_length);
cout << "t = 5 → subtreeRoot: " << root1 << ", I: [ ";
for (int pos: V1) cout << pos << " ";
cout << "]\n";

// 示例2: t=13 (1101)
auto [root2, V2] = TEalgorithm(13, bit_length);
cout << "t = 13 → subtreeRoot: " << root2 << ", I: [ ";
for (int pos: V2) cout << pos << " ";
cout << "]\n";

// 示例3: t=7 (0111)
auto [root3, V3] = TEalgorithm(7, bit_length);
cout << "t = 7 → subtreeRoot: " << root3 << ", I: [ ";
for (int pos: V3) cout << pos << " ";
cout << "]\n";

printf("\n================================================\n");
for (int i = 0; i < pow(2, bit_length); i++)
{
    auto [root, V] = TEalgorithm(i, bit_length);
    cout << "t = " << i << "\t" << bitset<32>(i).to_string().substr(32 - bit_length) << " → subtreeRoot: " << root << ", I: [ ";
    for (int pos: V) cout << pos << " ";
    cout << "]\n";
}
```

```shell
t = 5 → subtreeRoot: 0, I: [ 0 1 2 3 ]
t = 13 → subtreeRoot: 12, I: [ 2 3 ]
t = 7 → subtreeRoot: 0, I: [ 0 1 2 3 ]

================================================
t = 0   0000 → subtreeRoot: 0, I: [ 0 1 2 3 ]
t = 1   0001 → subtreeRoot: 0, I: [ 0 1 2 3 ]
t = 2   0010 → subtreeRoot: 0, I: [ 0 1 2 3 ]
t = 3   0011 → subtreeRoot: 0, I: [ 0 1 2 3 ]
t = 4   0100 → subtreeRoot: 0, I: [ 0 1 2 3 ]
t = 5   0101 → subtreeRoot: 0, I: [ 0 1 2 3 ]
t = 6   0110 → subtreeRoot: 0, I: [ 0 1 2 3 ]
t = 7   0111 → subtreeRoot: 0, I: [ 0 1 2 3 ]
t = 8   1000 → subtreeRoot: 8, I: [ 1 2 3 ]
t = 9   1001 → subtreeRoot: 8, I: [ 1 2 3 ]
t = 10  1010 → subtreeRoot: 8, I: [ 1 2 3 ]
t = 11  1011 → subtreeRoot: 8, I: [ 1 2 3 ]
t = 12  1100 → subtreeRoot: 12, I: [ 2 3 ]
t = 13  1101 → subtreeRoot: 12, I: [ 2 3 ]
t = 14  1110 → subtreeRoot: 14, I: [ 3 ]
t = 15  1111 → subtreeRoot: -1, I: [ ]
```

#### 三、密钥更新测试
```C++
int leaf_node = 8;
int time_period = 9;

BinaryTree bt(leaf_node);
cout<<"-------------------------------------------------\n";
cout << "Binary Tree Structure:" << '\n';
bt.printTree();
cout<<"-------------------------------------------------\n";

cout << "time_period = " << time_period << '\n';

// 示例1
vector <pair<int, int>> RL1 = {{8, 1}};
set<int> Y1 = bt.KUNodes(RL1, time_period);
cout << "KUNodes Result (RL={(8,1)}): Y = [ ";
for (int node: Y1) cout << node << " ";
cout << "]\n";

// 示例2
vector <pair<int, int>> RL2;
set<int> Y2 = bt.KUNodes(RL2, time_period);
cout << "KUNodes Result (empty RL): Y = [ ";
for (int node: Y2) cout << node << " ";
cout << "]\n";

// 示例3：
vector <pair<int, int>> RL3 = {{8, 0}, {11, 1}};
set<int> Y3 = bt.KUNodes(RL3, time_period);
cout << "KUNodes Result (RL={(8,0),(11,1)}): Y = [ ";
for (int node: Y3) cout << node << " ";
cout << "]\n";


// 示例4
vector <pair<int, int>> RL4 = {{8, 0}, {9, 1}, {14, 10}};
set<int> Y4 = bt.KUNodes(RL4, time_period);
cout << "KUNodes Result (RL={(8,0),(9,1)}): Y = [ ";
for (int node: Y4) cout << node << " ";
cout << "]\n";
```

```shell
-------------------------------------------------
Binary Tree Structure:
└── 1
    ├── 2
    │   ├── 4
    │   │   ├── 8*
    │   │   └── 9*
    │   └── 5
    │       ├── 10*
    │       └── 11*
    └── 3
        ├── 6
        │   ├── 12*
        │   └── 13*
        └── 7
            ├── 14*
            └── 15*
-------------------------------------------------
time_period = 9
(8,1) X = [ 1 2 4 8 ]
KUNodes Result (RL={(8,1)}): Y = [ 3 5 9 ]
KUNodes Result (empty RL): Y = [ 1 ]
(8,0) X = [ 1 2 4 8 ]
(11,1) X = [ 1 2 5 11 ]
KUNodes Result (RL={(8,0),(11,1)}): Y = [ 3 9 10 ]
(8,0) X = [ 1 2 4 8 ]
(9,1) X = [ 1 2 4 9 ]
KUNodes Result (RL={(8,0),(9,1)}): Y = [ 3 5 ]
```


### PBC 库基础操作指南
#### 1、配对（Pairing）声明
```
pairing_t pairing;  // 声明一个配对对象 
element_t e;        // 声明群/环上的元素变量（需指定具体类型）
pbc_param_t par;
```

#### 2、初始化函数
```
// 从标准输入初始化配对参数（需提前准备PBC格式的配对参数）
pairing_init_inp_str(pairing, stdin);
pbc_param_init_set_str(par, param); // char *param
pairing_init_pbc_param(pairing, par);
 
// 初始化元素到不同群/环：
element_init_Zr(e, pairing);  // 初始化到整数环 Zr（注意 'Z' 大写）
element_init_G1(e, pairing);  // 初始化到群 G1 
element_init_G2(e, pairing);  // 初始化到群 G2 
element_init_GT(e, pairing);  // 初始化到目标群 GT 
```

#### 3、随机数与哈希映射
```
element_random(e);                     // 生成群/环上的随机元素 
element_from_hash(e, void *data, int len);  // 将哈希值映射到群中，参数：输出元素 | 哈希数据指针 | 数据长度（字节）
```

#### 4、算术运算
```
// 基础运算 
element_add(n, a, b);     // 加法: n = a + b 
element_mul(n, a, b);     // 乘法: n = a * b 
element_neg(n, a);        // 取负: n = -a 
element_square(n, a);     // 平方: n = a² 
element_invert(n, a);     // 取逆: n = a⁻¹ 
 
// 域/环上的特殊运算 
element_mul_zn(c, a, z);  // 数乘: c = z * a（z ∈ Zr，顺序固定）
element_pow_zn(x, a, n);  // 指数: x = aⁿ 
element_pow2_zn(x, a1, n1, a2, n2);  // 联合指数: x = a1ⁿ¹ * a2ⁿ²（优化速度）

// 配对运算
element_pairing(out, in1, in2);       // 计算配对: out = e(in1, in2)
pairing_apply(out, in1, in2, pairing); // 功能同上，显式指定配对对象，两者实际等效，后者更明确上下文 
```

#### 5、工具函数
```
element_cmp(a, b);                // 比较元素：相等返回0，否则返回1 
element_length_in_bytes(e);       // 返回元素的字节长度 
element_printf("e = %B\n", e);    // 格式化输出元素（%B为专用占位符）
pbc_get_time();                   // 获取系统时间（等效于标准get_time()）
 
// 内存释放（必须调用以避免泄漏）
element_clear(e);                 // 释放元素内存 
pairing_clear(pairing);           // 释放配对对象内存 
```


## :alarm_clock: TODO

- 具体代码，待论文录用上传
- 具体代码，待论文录用上传


## License

如果学到了，**不要忘记点个Star** :sparkling_heart:

Copyright :copyright:2024 [Aptx4869AC](https://github.com/Aptx4869AC)