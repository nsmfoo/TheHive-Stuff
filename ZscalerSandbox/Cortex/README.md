# Zscaler Sandbox

This analyzer let's you use the Zscaler Sandbox API to analyze files.

The Sandbox can handle various types of files, for a full list see: https://help.zscaler.com/zia/about-sandbox

As the Sandbox does not accept password protected archive files. If a password protected zip archive is detected, the file will be unpacked using the supplied password before being submitted. Zip archives without a password set, they will be submitted as-is.

There is a quota for the amount of samples you can submit for a given day, the script will alert you if you have utlized it all. Please note that the daily quota is cut in half due to each lookup to retrive the report also deducts from the quota ... 

### General requirements

You will need to have an active Zscaler ZIA subscription and a sandbox policy configured to be able to utilize this analyzer.

### Known bugs 

Currently the final report, does not always show all the data that you can see in the raw report. This comes from one or several of the following "issues"

1) I don't understand AngularJS
2) There is a bug in AngularJS
3) The data from the Zscaler Sandbox contains faulty formated JSON (does not seem to be the case ..)
4) TheHive contains a bug ..

Pick and mix as you see fit (but if you can find the issue, please let me know)
