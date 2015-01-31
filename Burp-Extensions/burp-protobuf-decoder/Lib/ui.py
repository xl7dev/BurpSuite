from java.awt import Dimension, GridBagConstraints, GridBagLayout, Insets
from java.awt.event import ActionListener
from java.lang import Boolean, Double

from javax.swing import DefaultCellEditor, JButton, \
        JComboBox, JPanel, JScrollPane, JTable
from javax.swing.table import DefaultTableModel, TableRowSorter

from burp import IParameter

from base64 import b64encode, b64decode, urlsafe_b64encode, urlsafe_b64decode
from binascii import hexlify, unhexlify
from zlib import compress, decompress


PARAMETER_TYPES = {
    'PARAM_BODY': IParameter.PARAM_BODY,
    'PARAM_COOKIE': IParameter.PARAM_COOKIE,
    'PARAM_JSON': IParameter.PARAM_JSON,
    'PARAM_MULTIPART_ATTR': IParameter.PARAM_MULTIPART_ATTR,
    'PARAM_URL': IParameter.PARAM_URL,
    'PARAM_XML': IParameter.PARAM_XML,
    'PARAM_XML_ATTR': IParameter.PARAM_XML_ATTR,
}

RULES = {

    '': lambda x:x,
    'zlib compress': compress,
    'zlib decompress': decompress,
    'base64 encode': b64encode,
    'base64 decode': b64decode,
    'url-base64 encode': urlsafe_b64encode,
    'url-base64 decode': urlsafe_b64decode,
    'hex encode': hexlify,
    'hex decode': unhexlify,

}


class ParameterProcessingRulesTable(JPanel):
    def __init__(self, extender=None, *rows):
        self.extender = extender

        self.table = table = JTable(ParameterProcessingRulesTableModel(*rows))
        table.setPreferredScrollableViewportSize(Dimension(500, 70))
        table.setRowSorter(TableRowSorter(table.getModel()))
        table.setFillsViewportHeight(True)

        gridBagLayout = GridBagLayout()
        gridBagLayout.columnWidths = [0, 0, 25, 0 ]
        gridBagLayout.rowHeights = [0, 0, 0, 0]
        gridBagLayout.columnWeights = [0.0, 1.0, 1.0, Double.MIN_VALUE]
        gridBagLayout.rowWeights = [0.0, 0.0, 0.0, Double.MIN_VALUE]
        self.setLayout(gridBagLayout)

        addButton = JButton("Add")
        addButton.addActionListener(AddRemoveParameterListener(table))
        addButtonConstraints = GridBagConstraints()
        addButtonConstraints.fill = GridBagConstraints.HORIZONTAL
        addButtonConstraints.insets = Insets(0, 0, 5, 5) 
        addButtonConstraints.gridx = 0
        addButtonConstraints.gridy = 0
        self.add(addButton, addButtonConstraints)

        removeButton = JButton("Remove")
        removeButton.addActionListener(AddRemoveParameterListener(table))
        removeButtonConstraints = GridBagConstraints()
        removeButtonConstraints.fill = GridBagConstraints.HORIZONTAL
        removeButtonConstraints.insets = Insets(0, 0, 5, 5) 
        removeButtonConstraints.gridx = 0
        removeButtonConstraints.gridy = 1
        self.add(removeButton, removeButtonConstraints)

        upButton = JButton("Up")
        upButton.addActionListener(AddRemoveParameterListener(table))
        upButtonConstraints = GridBagConstraints()
        upButtonConstraints.fill = GridBagConstraints.HORIZONTAL
        upButtonConstraints.insets = Insets(0, 0, 5, 5) 
        upButtonConstraints.gridx = 0
        upButtonConstraints.gridy = 2
        self.add(upButton, upButtonConstraints)

        downButton = JButton("Down")
        downButton.addActionListener(AddRemoveParameterListener(table))
        downButtonConstraints = GridBagConstraints()
        downButtonConstraints.fill = GridBagConstraints.HORIZONTAL
        downButtonConstraints.anchor = GridBagConstraints.NORTH
        downButtonConstraints.insets = Insets(0, 0, 5, 5) 
        downButtonConstraints.gridx = 0
        downButtonConstraints.gridy = 3
        self.add(downButton, downButtonConstraints)

        scrollPane = JScrollPane(table)
        scrollPaneConstraints = GridBagConstraints()
        scrollPaneConstraints.gridwidth = 2
        scrollPaneConstraints.gridheight = 5
        scrollPaneConstraints.insets = Insets(0, 0, 5, 5)
        scrollPaneConstraints.anchor = GridBagConstraints.NORTHWEST 
        scrollPaneConstraints.gridx = 1
        scrollPaneConstraints.gridy = 0
        self.add(scrollPane, scrollPaneConstraints)

        self.initParameterColumn(table)
        self.initColumnSizes(table)

    def initParameterColumn(self, table):
        parameterTypes = JComboBox(sorted(PARAMETER_TYPES.keys()))
        parameterTypes.setSelectedItem('PARAM_BODY')
        parameterColumn = table.getColumnModel().getColumn(0)
        parameterColumn.setCellEditor(DefaultCellEditor(parameterTypes))

        whenTypes = JComboBox(['Before', 'After'])
        whenTypes.setSelectedItem('Before')
        whenColumn = table.getColumnModel().getColumn(2)
        whenColumn.setCellEditor(DefaultCellEditor(whenTypes))

        ruleTypes = JComboBox(sorted(RULES.keys()))
        ruleColumn = table.getColumnModel().getColumn(3)
        ruleColumn.setCellEditor(DefaultCellEditor(ruleTypes))
        return

    def initColumnSizes(self, table):
        model = table.getModel()
        values = model.DEFAULT_VALUES
        headers = model.COLUMN_NAMES

        headerRenderer = table.getTableHeader().getDefaultRenderer()

        for i, (header, value) in enumerate(zip(headers, values)):
            column = table.getColumnModel().getColumn(i)

            comp = headerRenderer.getTableCellRendererComponent(
                    None, header, False, False, 0, 0)

            headerWidth = comp.getPreferredSize().width

            comp = table.getDefaultRenderer(
                    model.getColumnClass(i)).getTableCellRendererComponent(
                            table, value, False, False, 0, i)

            cellWidth = comp.getPreferredSize().width
            column.setPreferredWidth(max([headerWidth, cellWidth]))

        return

    def getParameterRules(self):
        rules = {}
        for ptype, name, when, rule, enabled in self.table.getModel().data:
            if enabled:
                rules.setdefault(name, {}).setdefault(when.lower(), []).append(RULES.get(rule, ''))
        return rules

    @property
    def rules(self):
        return self.table.getModel().data


class ParameterProcessingRulesTableModel(DefaultTableModel):
    DEFAULT_VALUES = ('PARAM_BODY', '', 'Before', '', Boolean(0))
    COLUMN_NAMES = ('Type', 'Name', 'When', 'Rule', 'Enabled')

    def __init__(self, *rows):
        self.data = list(rows)

    def getColumnCount(self):
        return len(self.COLUMN_NAMES)

    def getRowCount(self):
        return len(self.data)

    def getColumnName(self, col):
        return self.COLUMN_NAMES[col]

    def getValueAt(self, row, col):
        return self.data[row][col] if self.data else None

    def getColumnClass(self, c):
        return self.getValueAt(0, c).__class__

    def setValueAt(self, value, row, col):
        if isinstance(value, bool):
            self.data[row][col] = Boolean(value)
        else:
            self.data[row][col] = value if value else ''
        self.fireTableCellUpdated(row, col)
        return

    def isCellEditable(self, row, col):
        return True

    def addRow(self, row=None):
        self.data.append(row or ['PARAM_BODY', '', 'Before', '', Boolean(0)])
        self.fireTableRowsInserted(len(self.data) - 1, len(self.data) - 1)
        return

    def removeRow(self, row):
        if not self.data:
            return

        if row < 0:
            row = len(self.data) - 1

        del self.data[row]
        self.fireTableRowsDeleted(row, row)
        return

    def moveRowUp(self, row):
        if row < 1:
            return False
        self.data[row - 1:row + 1] = reversed(self.data[row - 1: row + 1])
        self.fireTableRowsUpdated(row - 1, row)
        return True

    def moveRowDown(self, row):
        if row >= len(self.data) - 1:
            return False
        self.data[row:row + 2] = reversed(self.data[row:row + 2])
        self.fireTableRowsUpdated(row, row + 1)
        return True


class AddRemoveParameterListener(ActionListener):
    def __init__(self, table):
        self.table = table

    def actionPerformed(self, event):
        if event.getActionCommand() == 'Add':
            self.table.getModel().addRow()
        elif event.getActionCommand() == 'Remove':
            row = self.table.getSelectedRow()
            self.table.getModel().removeRow(row)
        elif event.getActionCommand() == 'Up':
            row = self.table.getSelectedRow()
            if self.table.getModel().moveRowUp(row):
                self.table.setRowSelectionInterval(row - 1, row - 1)
        elif event.getActionCommand() == 'Down':
            row = self.table.getSelectedRow()
            if self.table.getModel().moveRowDown(row):
                self.table.setRowSelectionInterval(row + 1, row + 1)
        return
