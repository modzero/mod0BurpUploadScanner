from javax.swing import JFileChooser, JButton
from java.awt.event import ActionListener
from helpers.FloydsHelpers import FloydsHelpers

class FileChooserButton(JButton, ActionListener):
    def setup(self, field, button_name):
        self.field = field
        self.addActionListener(self)
        self.setText(button_name)

    def actionPerformed(self, actionEvent):
        chooser = JFileChooser()
        # chooser.setCurrentDirectory(".")
        chooser.setDialogTitle("Choose file")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setAcceptAllFileFilterUsed(False)
        if chooser.showOpenDialog(self) == JFileChooser.APPROVE_OPTION:
            # print(chooser.getCurrentDirectory())
            # print(chooser.getSelectedFile())
            self.field.setText(FloydsHelpers.u2s(chooser.getSelectedFile().toString()))
        else:
            print("No file selected")
