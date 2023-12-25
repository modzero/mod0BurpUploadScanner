
from helpers.FloydsHelpers import FloydsHelpers
from ui.FileChooserButton import FileChooserButton
from javax.swing import JFileChooser
from javax.swing import JButton
from java.awt.event import ActionListener

class DirectoryChooserButton(JButton, ActionListener):
    def setup(self, field, button_name):
        self.field = field
        self.addActionListener(self)
        self.setText(button_name)

    def actionPerformed(self, actionEvent):
        chooser = JFileChooser()
        # chooser.setCurrentDirectory(".")
        chooser.setDialogTitle("Choose directory")
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        chooser.setAcceptAllFileFilterUsed(False)
        if chooser.showOpenDialog(self) == FileChooserButton.APPROVE_OPTION:
            # print(chooser.getCurrentDirectory())
            # print(chooser.getSelectedFile())
            self.field.setText(FloydsHelpers.u2s(chooser.getSelectedFile().toString()))
        else:
            print("No directory selected")
