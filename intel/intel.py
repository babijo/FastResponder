'''
Created on 16 janv. 2015

@author: slarinier
'''
# -*- coding: utf-8 -*-
###############################################################################
#
#   FastResponder - Collect artefacts Windows for First Reponder
#    cert@sekoia.fr - http://www.sekoia.fr
#   Copyright (C) 2014  SEKOIA
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
###############################################################################

from __future__ import unicode_literals

import datetime
import hashlib
import logging
from os import listdir
import os
import sys
import traceback
import yara
from petools.peparser import PeParser
from utils import     get_int_from_reversed_string, look_for_outlook_dirs, get_userprofiles_from_reg,\
                    look_for_files, zip_archive, get_csv_writer, write_to_csv, record_sha256_logs, process_sha256
from win32com.shell import shell, shellcon


class _intel(object):
    def __init__(self,params):
        self.userprofiles=None
        self.public=None
        self.systemroot=params['system_root']
        self.computer_name=params['computer_name']
        self.output_dir=params['output_dir']
        self.logger=params['logger']
        if 'yara_rules' in params:
            self.yara_rules=params['yara_rules']
            self.rules = yara.compile(filepath=self.yara_rules)
        if 'extractCertif' in params:
            self.extractCerfif=params['extractCertif']    
    def _extractSignature(self,filename):
        matches=self.rules.match(data=open(filename,'rb').read())
        issuer=''
        subject=''
        for m in matches:
            if str(m)=='mz_executable':
                pe = PeParser(filename)
                if pe.signature:
                    issuer=pe.signature.getissuer()
                    subject=pe.signature.getsubject()
                    return issuer,subject
        return issuer,subject
    def csv_yara(self,path=os.environ['SYSTEMDRIVE']+'\\'):
        try:
            if os.path.isdir(path):
                list_files=os.listdir(unicode(path))
        except Exception as e:
            self.logger.warn(traceback.format_exc().decode(sys.stdin.encoding))
            return
        for f in list_files:
            d=os.path.join(path,f)
            if os.path.isdir(d):
                self.csv_yara(d)
            try:
                if os.path.isfile(d):    
                    matches = self.rules.match(data=open(d,'rb').read())
                    if matches: 
                        sha = process_sha256(d)
                        for m in matches.get('main',[]):
                            with open(self.output_dir + '\\' + self.computer_name + '_yara.csv', 'ab') as output:
                                csv_writer = get_csv_writer(output)    
                                write_to_csv(['yara',d,f,m,sha.hexdigest()], csv_writer)
            except Exception as e:
                self.logger.error(traceback.format_exc())
    
    def csv_sha256(self,path=os.environ['SYSTEMDRIVE']+'\\'):
        try:
            if os.path.isdir(path):
                list_files=os.listdir(unicode(path))
        except Exception as e:
            self.logger.error(traceback.format_exc().decode(sys.stdin.encoding))    
            return
        for f in list_files:
            d=os.path.join(path,f)
            if os.path.isdir(d):
                self.csv_sha256(d)
            elif os.path.isfile(d):
                try:
                    sha = process_sha256(d)
                    issuer=''
                    subject=''
                    if self.extractCerfif:
                        issuer,subject=self._extractSignature(d)
                    with open(self.output_dir + '\\' + self.computer_name + '_sha256.csv', 'ab') as output:
                        csv_writer = get_csv_writer(output)    
                        write_to_csv(['sha256',d,sha.hexdigest(),issuer,subject], csv_writer)
                except Exception as e:
                    self.logger.error(traceback.format_exc())