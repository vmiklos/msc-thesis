Sub Main
	'use this if you want to store the menu globally
	'oModMan = createUnoService("com.sun.star.frame.ModuleManager")
	'sModuleIndentifyer = oModMan.identify(ThisComponent)
	'oCfgMgrSupplier = createUnoService("com.sun.star.ui.ModuleUIConfigurationManagerSupplier")
	'oCfgMgr = oCfgMgrSupplier.getUIConfigurationManager(sModuleIndentifyer )
	'use this if you want to store the menu only with the document
	oCfgMgr = ThisComponent.getUIConfigurationManager
	'xray oCfgMgr


	'The code below is mainly from Carsten Driesner ( http://api.openoffice.org/servlets/ReadMsg?list=dev&msgNo=16882 )
	' The name of our new custom toolbar. A custom toolbar name MUST
	' start with "custom_"!
	sToolbar = "private:resource/toolbar/custom_lpsp"

	' Create a settings container which will define the structure of our new
	' custom toolbar.
	oToolbarSettings = oCfgMgr.createSettings()
   
	' Set a title for our new custom toolbar
	oToolbarSettings.UIName = "LPSP toolbar"
   
	' Create a buttons for our new custom toolbar
	oToolbarSettings.insertByIndex( oToolbarSettings.getCount(), CreateToolbarItem("vnd.sun.star.script:TestLib.Module1.Test?language=Basic&location=application", "button1"))
   
	' Set the settings for our new custom toolbar. (replace/insert)
	If ( oCfgMgr.hasSettings( sToolbar )) then
		oCfgMgr.replaceSettings( sToolbar, oToolbarSettings )
	Else
	  	oCfgMgr.insertSettings( sToolbar, oToolbarSettings )
	Endif
	oCfgMgr.store
End Sub

Function CreateToolbarItem( Command as String, Label as String ) as Variant
	Dim aToolbarItem(3) as new com.sun.star.beans.PropertyValue

	aToolbarItem(0).Name = "CommandURL"
	aToolbarItem(0).Value = Command
	aToolbarItem(1).Name = "Label"
	aToolbarItem(1).Value = Label
	aToolbarItem(2).Name = "Type"
	aToolbarItem(2).Value = 0
	aToolbarItem(3).Name = "Visible"
	aToolbarItem(3).Value = true

	CreateToolbarItem = aToolbarItem()
End Function

Sub Test
   MsgBox "Test"
End Sub
