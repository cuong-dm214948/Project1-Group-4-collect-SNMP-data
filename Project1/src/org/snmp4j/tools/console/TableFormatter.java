/*_############################################################################
  _## 
  _##  SNMP4J - TableFormatter.java  
  _## 
  _##  Copyright (C) 2003-2022  Frank Fock (SNMP4J.org)
  _##  
  _##  Licensed under the Apache License, Version 2.0 (the "License");
  _##  you may not use this file except in compliance with the License.
  _##  You may obtain a copy of the License at
  _##  
  _##      http://www.apache.org/licenses/LICENSE-2.0
  _##  
  _##  Unless required by applicable law or agreed to in writing, software
  _##  distributed under the License is distributed on an "AS IS" BASIS,
  _##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  _##  See the License for the specific language governing permissions and
  _##  limitations under the License.
  _##  
  _##########################################################################*/
package org.snmp4j.tools.console;

import org.snmp4j.smi.AssignableFromInteger;
import org.snmp4j.smi.AssignableFromLong;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

public class TableFormatter {

    private PrintStream printer;
    private List<Object[]> buffer = new ArrayList<>();
    private int limit = 5;
    private int[] colSizes;
    private int defaultColSize = 16;
    private int maxLineLength = 80;
    private String separator = " ";

    private boolean compact = false;
    private boolean leftAlign = false;

    public TableFormatter(PrintStream printer,
                          int defaultColumnSize, int maxLineLength,
                          String separator) {
        this.printer = printer;
        this.maxLineLength = maxLineLength;
        this.defaultColSize = defaultColumnSize;
        if (separator != null) {
            this.separator = separator;
        }
    }

    public void setBufferSize(int limit) {
        this.limit = Math.max(limit, 1);
    }

    public void setCompact(boolean compact) {
        this.compact = compact;
    }

    public synchronized void addRow(Object[] columns) {
        buffer.add(columns);
        if (buffer.size() > limit) {
            flush();
        }
    }

    private void computeColumnSizes() {
        int numcols = 0;
        for (Object[] aBuffer1 : buffer) {
            Object o = aBuffer1;
            numcols = Math.max(numcols, ((Object[]) o).length);
        }
        colSizes = new int[numcols];
        for (Object[] aBuffer : buffer) {
            Object o = aBuffer;
            Object[] c = (Object[]) o;
            for (int j = 0; j < c.length; j++) {
                String s = getString(c[j]);
                colSizes[j] = Math.max(s.length(), colSizes[j]);
            }
        }
    }

    private static String getString(Object o) {
        if (o instanceof VariableBinding) {
            return ((VariableBinding) o).toValueString();
        }
        if (o == null) {
            return "";
        }
        return o.toString();
    }

    public synchronized void flush() {
        if (colSizes == null) {
            computeColumnSizes();
        }
        printBuffer();
        buffer.clear();
    }

    public void setLeftAlign(boolean leftAlign) {
        this.leftAlign = leftAlign;
    }

    private void printBuffer() {
        for (Object[] aBuffer : buffer) {
            Object o = aBuffer;
            Object[] c = (Object[]) o;
            int rsz = 0;
            for (int j = 0; j < c.length; j++) {
                String s = getString(c[j]);
                int sz = s.length();
                int tsz = (j < colSizes.length) ? colSizes[j] : defaultColSize;
                rsz += tsz + separator.length();
                if (compact) {
                    printer.print(s);
                    printer.print(separator);
                } else {
                    boolean padded = false;
                    if (!leftAlign && (isNumber(c[j]))) {
                        // padding
                        for (int k = 0; k < tsz - sz; k++) {
                            printer.print(' ');
                        }
                        padded = true;
                    }
                    printer.print(s);
                    if (rsz > maxLineLength) {
                        printer.println();
                        rsz = 0;
                    } else if (!padded) {
                        printer.print(separator);
                        // padding
                        for (int k = 0; k < tsz - sz; k++) {
                            printer.print(' ');
                        }
                    } else {
                        printer.print(separator);
                    }
                }
            }
            printer.println();
        }
    }

    private boolean isNumber(Object o) {
        if (o instanceof VariableBinding) {
            Variable v = ((VariableBinding) o).getVariable();
            if ((v instanceof AssignableFromLong) ||
                    (v instanceof AssignableFromInteger)) {
                return true;
            }
        }
        return false;
    }

    public void setSeparator(String separator) {
        this.separator = separator;
    }
}
