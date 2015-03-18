# -*- coding: utf-8 -*-
"""
Created on Wed Jan 15 13:21:56 2014

@author: slarinier
"""
from __future__ import unicode_literals
from logs import _EventLogs

class WindowsXPEvt(_EventLogs):
	def __init__(self,params):
		super(WindowsXPEvt,self).__init__(params)
	
	def csv_event_logs(self):
		super(WindowsXPEvt, self)._csv_event_logs(True)