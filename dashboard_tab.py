import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class DashboardTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.create_widgets()
    def create_widgets(self):
        fig, ax = plt.subplots(figsize=(5,3))
        ax.plot([1,2,3,4], [10,20,15,30], marker='o')
        ax.set_title("Analytics Chart")
        canvas = FigureCanvasTkAgg(fig, master=self)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
