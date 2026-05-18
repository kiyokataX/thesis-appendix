import collections
import string
import matplotlib.pyplot as plt

def calculate_frequency(text: str) -> dict[str,float]:
    """计算字符串内各个字母频率的函数

    Args:
        text (str): 输入的字符串

    Returns:
        dict[str,float]: 返回一个字典,键是字母,值是频率
    """
    #数据清洗
    clean_text = [char for char in text.upper() if char in string.ascii_uppercase]
    
    #防止除以0
    if not clean_text:
        return {}

    #用Counter方法计数
    char_count = collections.Counter(clean_text)
    # 统计字符串中所有字符的总数
    total_chars = sum(char_count.values())
    
    # 计算每个字符的频率
    frequency = {char: count / total_chars for char, count in char_count.items()}
    sorted_frequency = dict(sorted(frequency.items(), key=lambda item: item[1], reverse=True))
    
    return sorted_frequency

def plot_frequency(frequency: dict[str, float], title: str = "Letter Frequency Analysis"):
    """使用matplotlib来绘制频率分布直方图

    Args:
        frequency (dict[str, float]): 一个字典，键是字母，值是对应的频率。
        title (str, optional): 图表的标题。默认为 "Letter Frequency Analysis"。
    
    Returns:
        None: 该函数不返回值，而是直接显示图表。
    """
    if not frequency:
        print("没有数据画图!")
        return
    
    #分离字母和频率作为X Y
    letters = list(frequency.keys())
    freqs = list(frequency.values())


    plt.bar(letters, freqs)
    plt.xlabel('Letters')
    plt.ylabel('Frequency')
    plt.title(title)
   
    # 显示具体数值在柱子上方 (可选)
    for i, v in enumerate(freqs):
        plt.text(i, v + 0.001, f"{v:.3f}", ha='center', fontsize=8)
    
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.show()


if __name__ == "__main__":
    # 测试用例：一段英文样例文本
    sample_text = """
    Cryptography is the practice and study of techniques for secure communication 
    in the presence of third parties called adversaries.
    """
    
    print("正在计算频率...")
    freqs = calculate_frequency(sample_text)
    
    print("\n结果 (Top 5):")
    for char, freq in list(freqs.items())[:5]:
        print(f"'{char}': {freq:.4f}")
        
    print("\n正在生成图表...")
    plot_frequency(freqs, "Sample Text Frequency")