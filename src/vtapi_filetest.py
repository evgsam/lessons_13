import requests
import json
import os
from dotenv import load_dotenv
import time 

load_dotenv()
api_key = os.getenv("VT_API_KEY")
base_url = "https://www.virustotal.com/api/v3/"
url = f"{base_url}/files"
scan_target="/home/user/python_projects/lessons_13/test_files/image.png"

headers = {
    "accept": "application/json",
    "x-apikey": api_key
}
def upload_and_poll(max_retries=3, delay=15):
    """Загружает файл и ждёт результат анализа с повторными попытками"""
    
    for attempt in range(max_retries):
        print(f"Попытка загрузки #{attempt + 1}/{max_retries}")
        
        # 1. Загрузка файла
        with open(scan_target, "rb") as file:
            files = {"file": (scan_target, file)}
            response = requests.post(f"{base_url}/files", headers=headers, files=files)
        
        data = response.json()
        print("Upload response:", json.dumps(data, indent=2, ensure_ascii=False))
        
        # Проверка на ошибку ConflictError
        if "error" in data and data["error"]["code"] == "ConflictError":
            print(f"VT не успел обработать: {data['error']['message']}")
            if attempt < max_retries - 1:
                print(f"Ждём {delay} сек и повторим...")
                time.sleep(delay)
                continue
            else:
                print("Все попытки исчерпаны. Попробуйте позже.")
                return None
        
        # Успешная загрузка — достаём ID анализа
        analysis_id = data["data"]["id"]
        print(f"Анализ запущен, ID: {analysis_id}")
        break
    else:
        return None
    
    # 2. Ждём завершения анализа (поллинг)
    analysis_url = f"{base_url}/analyses/{analysis_id}"
    print("Ждём завершения анализа...")
    time.sleep(30)  # базовая пауза
    
    # 3. Получаем результат
    analysis_resp = requests.get(analysis_url, headers=headers)
    analysis_data = analysis_resp.json()
    print("Analysis response:", json.dumps(analysis_data, indent=2, ensure_ascii=False))
    
    # 4. СОХРАНЕНИЕ ОТЧЁТА
    # Получаем имя файла без пути и расширения
    file_name = os.path.splitext(os.path.basename(scan_target))[0]
    file_dir = os.path.dirname(scan_target)
    
    # Имя отчёта: "имя_файла_report.json"
    report_filename = f"{file_name}_report.json"
    report_path = os.path.join(file_dir, report_filename)
    
    # Сохраняем полный отчёт
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(analysis_data, f, indent=2, ensure_ascii=False)
    
    print(f"Отчёт сохранён: {report_path}")
    
    return analysis_data

# Запуск
result = upload_and_poll()