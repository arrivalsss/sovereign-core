import time

class ResourceBudgetExceeded(Exception):
    pass

class ExecutionBudget:
    def __init__(self, max_time_seconds=0.1, max_total_bytes=100_000, max_operations=50):
        self.deadline = time.monotonic() + max_time_seconds
        self.max_total_bytes = max_total_bytes
        self.max_operations = max_operations
        self.consumed_bytes = 0
        self.operations_count = 0

    def record_operation(self, output_bytes_len: int):
        """فحص وتحديث الميزانية مع كل عملية فك أو معالجة"""
        self.operations_count += 1
        self.consumed_bytes += output_bytes_len

        # 1. التحقق من المهلة الزمنية
        if time.monotonic() > self.deadline:
            raise ResourceBudgetExceeded("[BUDGET_EXCEEDED] Execution time limit reached.")

        # 2. التحقق من عدد العمليات
        if self.operations_count > self.max_operations:
            raise ResourceBudgetExceeded("[BUDGET_EXCEEDED] Maximum operations threshold exceeded.")

        # 3. التحقق من حجم البيانات الناتج (منع Zip/Decompress Bombs)
        if self.consumed_bytes > self.max_total_bytes:
            raise ResourceBudgetExceeded("[BUDGET_EXCEEDED] Decompressed memory limit exceeded.")

if __name__ == "__main__":
    print("[TEST] Running Resource Budget Limits...")
    budget = ExecutionBudget(max_time_seconds=0.05, max_total_bytes=5000, max_operations=10)
    
    # اختبار تجاوز الحجم
    try:
        for _ in range(20):
            budget.record_operation(600)  # سيتجاوز 5000 بايت في الدورة التاسعة
        print("[FAIL] Budget limit failed to trigger on memory bomb!")
    except ResourceBudgetExceeded as e:
        print(f"[PASS] Intercepted memory limit: {e}")

    # اختبار تجاوز المهلة الزمنية
    time_budget = ExecutionBudget(max_time_seconds=0.02)
    try:
        time.sleep(0.03)
        time_budget.record_operation(10)
        print("[FAIL] Budget limit failed to trigger on timeout!")
    except ResourceBudgetExceeded as e:
        print(f"[PASS] Intercepted timeout limit: {e}")

    print("[SUCCESS] Resource budget defense is active and verified.")
