import tkinter as tk
from tkinter import messagebox

from xdr_graph.desktop import main


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # windowed EXE에서 시작 예외가 콘솔 뒤에 숨지 않게 사용자 문장으로 알린다.
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "WeaveXDR를 시작하지 못했습니다",
            f"프로그램 시작 중 문제가 발생했습니다.\n\n{type(error).__name__}: {error}\n\n로그 폴더에서 자세한 원인을 확인할 수 있습니다.",
        )
        root.destroy()
        raise
