# -*- coding: utf-8 -*-
"""
Created on Wed Jan 15 13:21:56 2014

@author: slarinier
"""
from __future__ import unicode_literals
from logs import _EventLogs

class Windows7Evt(_EventLogs):
	def __init__(self,params):
		super(Windows7Evt,self).__init__(params)

	def csv_event_logs(self):
		super(Windows7Evt,self)._csv_event_logs(False)