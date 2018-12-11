import Foundation

struct SkipSel {
    static let cxx_destruct = ".cxx_destruct"
}

enum Regex: String {
    case clsSelName = "\\sname.0x\\w+.(.+)",
    OCSelSig = "imp 0x\\w+ ([+|-]\\[.+\\s(.+)\\])",
    OCClassChunk = "\\sdata.+0x\\w+.\\(struct.class_ro_t.\\*\\)(?!.Swift.class)([\\s|\\S]*?)baseProtocols",
    swiftClassChunk = "\\sdata.+0x\\w+.\\(struct.class_ro_t.\\*\\).Swift class([\\s|\\S]*?)baseProtocols",
    referencedSel = "__TEXT:__objc_methname:(.+)",
    classrefsChunk = "Contents.of.\\(__DATA,__objc_classrefs\\).section([\\s|\\S]*?)Contents.of",
    classlistChunk = "Contents.of.\\(__DATA,__objc_classlist\\).section([\\s|\\S]*?)Contents.of",
    classrefClsName = "0\\w+.0x\\w+._OBJC_CLASS_\\$_(.+)"
    
    var regularExp: NSRegularExpression {
        return try! NSRegularExpression(pattern: rawValue)
    }
}

typealias SelInfo = (sel: String, impSig: String)

func systemCall(launchPath: String, arguments: [String]) -> String? {
    let process = Process()
    
    let outPipe = Pipe()
    process.standardOutput = outPipe
    if #available(OSX 10.13, *) {
        process.executableURL = URL(fileURLWithPath: launchPath)
    } else {
        process.launchPath = launchPath
    }
    process.arguments = arguments
    process.launch()
    
    let outdata = outPipe.fileHandleForReading.readDataToEndOfFile()
    let outputString = String(data: outdata, encoding: String.Encoding.utf8)
    return outputString
}

func verifiedMachOPath(_ path: String) -> String? {
    guard #available(OSX 10.12, *), FileManager.default.isReadableFile(atPath: path) else {
        return nil
    }
    
    // Apparently there is a bug in otool -- it doesn't seem to like executables
    // with spaces in the names. If this is the case, make a copy and analyze that.
    var machoPath = path
    
    let machoFile = (path as NSString).lastPathComponent
    if machoFile.contains(" ") {
        // don't remove the spaces, that could lead to an empty string
        let newFileName = machoFile.replacingOccurrences(of: " ", with: "_")
        let tempPath = FileManager.default.temporaryDirectory.appendingPathComponent(newFileName).path
        try? FileManager.default.copyItem(atPath: machoPath, toPath: tempPath)
        machoPath = tempPath
    }
    
    let outputString = systemCall(launchPath: "/usr/bin/file", arguments: ["-b", machoPath]) ?? ""
    guard outputString.hasPrefix("Mach-O") else {
        return nil
    }
    return machoPath
}

func referencedSelectors(_ machoPath: String) -> Set<String> {
    let referencedSelReg = Regex.referencedSel.regularExp
    let referencedSelInfo = systemCall(launchPath: "/usr/bin/otool",
                                       arguments: ["-v", "-s","__DATA", "__objc_selrefs", machoPath]) ?? ""
    let selResults = referencedSelReg.matches(in: referencedSelInfo, options: [], range: NSRange(referencedSelInfo.startIndex..., in: referencedSelInfo))
    
    var sels: Set<String> = []
    for selResult in selResults {
        let sel = String(referencedSelInfo[Range(selResult.range(at: 1), in: referencedSelInfo)!])
        guard !sel.isEmpty else { continue }
        sels.insert(sel)
    }
    
    return sels
}

func implementedMethods(machoInfo: String) -> [String: [String]] {
    let OCClassReg = Regex.OCClassChunk.regularExp
    let swiftClassReg = Regex.swiftClassChunk.regularExp
    
    let OCClassResults = OCClassReg.matches(in: machoInfo, options: [], range: NSRange(machoInfo.startIndex..., in: machoInfo))
    let swiftClassResults = swiftClassReg.matches(in: machoInfo, options: [], range: NSRange(machoInfo.startIndex..., in: machoInfo))
    
    var selInfos: [SelInfo] = []
    
    for OCClassResult in OCClassResults {
        let OCClassChunk = String(machoInfo[Range(OCClassResult.range(at: 1), in: machoInfo)!])
        let OCSelInfo = parseObjcClassChunk(OCClassChunk)
        if !OCSelInfo.isEmpty {
            selInfos.append(contentsOf: OCSelInfo)
        }
    }
    
    
    for swiftClassResult in swiftClassResults {
        let swiftClassChunk = String(machoInfo[Range(swiftClassResult.range(at: 1), in: machoInfo)!])
        let swiftSelInfo = parseSwiftClassChunk(swiftClassChunk)
        if swiftSelInfo.isEmpty { continue }
        
        selInfos.append(contentsOf: swiftSelInfo)
    }
    
    let selMapInfo = Dictionary(grouping: selInfos, by: { $0.sel }).mapValues { selInfos -> [String] in
        Array(Set(selInfos.map { $0.impSig }))
    }
    
    return selMapInfo
}

func parseObjcClassChunk(_ chunk: String) -> [SelInfo] {
    let OCSelSigReg = Regex.OCSelSig.regularExp
    let selCheckResults = OCSelSigReg.matches(in: chunk, options: [], range: NSRange(chunk.startIndex..., in: chunk))
    var selInfoArray: [SelInfo] = []
    
    for selCheckResult in selCheckResults {
        let impSig = String(chunk[Range(selCheckResult.range(at: 1), in: chunk)!])
        let sel = String(chunk[Range(selCheckResult.range(at: 2), in: chunk)!])
        if sel == SkipSel.cxx_destruct { continue }
        selInfoArray.append(SelInfo(sel: sel, impSig: impSig))
    }
    return selInfoArray
}

func parseSwiftClassChunk(_ chunk: String) -> [SelInfo] {
    let clsSelNameReg = Regex.clsSelName.regularExp
    guard let classNameResult = clsSelNameReg.firstMatch(in: chunk, options: [], range: NSRange(chunk.startIndex..., in: chunk)) else {
        return []
    }
    
    var className = String(chunk[Range(classNameResult.range(at: 1), in: chunk)!])
    
    if let swiftCls = systemCall(launchPath: "/usr/bin/xcrun", arguments: ["swift-demangle", "--compact",  className]) {
        className = swiftCls.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    
    let subChunk = (chunk as NSString).substring(from: classNameResult.range.location + classNameResult.range.length)
    let selCheckResults = clsSelNameReg.matches(in: subChunk, options: [], range: NSRange(subChunk.startIndex..., in: subChunk))
    var selInfoArray: [SelInfo] = []
    
    for selCheckResult in selCheckResults {
        let sel = String(subChunk[Range(selCheckResult.range(at: 1), in: subChunk)!])
        if sel == SkipSel.cxx_destruct { continue }
        
        let impSig = "[\(className) \(sel)]"
        selInfoArray.append(SelInfo(sel: sel, impSig: impSig))
    }
    
    return selInfoArray
}

func findUnusedMethods(machoPath: String, machoInfo: String, selWhiteList: [String]) -> [String] {
    var unusedMethods: [String] = []
    
    let implementedMethod = implementedMethods(machoInfo: machoInfo)
    let referencedSelector = Set(referencedSelectors(machoPath)).subtracting(selWhiteList)
    
    let implementedMethodSels = Set(implementedMethod.map { $0.key })
    let unusedMethodSels = implementedMethodSels.subtracting(referencedSelector)
    
    for unusedMethodSel in unusedMethodSels {
        guard let methods = implementedMethod[unusedMethodSel] else { continue }
        unusedMethods.append(contentsOf: methods)
    }
    
    let result = unusedMethods.sorted(by: <)
    return result
}

func findUnusedClass(machoInfo: String) -> [String] {
    
    let classrefsChunkReg = Regex.classrefsChunk.regularExp
    let classlistChunkReg = Regex.classlistChunk.regularExp
    let classNameReg = Regex.classrefClsName.regularExp
    
    var classrefsChunk = ""
    if let classrefsChunkResult = classrefsChunkReg.firstMatch(in: machoInfo, options: [], range: NSRange(machoInfo.startIndex..., in: machoInfo)) {
        classrefsChunk = String(machoInfo[Range(classrefsChunkResult.range(at: 1), in: machoInfo)!])
    }
    
    var classlistChunk = ""
    if let classlistChunkResult = classlistChunkReg.firstMatch(in: machoInfo, options: [], range: NSRange(machoInfo.startIndex..., in: machoInfo)) {
        classlistChunk = String(machoInfo[Range(classlistChunkResult.range(at: 1), in: machoInfo)!])
    }
    
    var allClsName: Set<String> = []
    var refedClsName: Set<String> = []
    
    let allClsResults = classNameReg.matches(in: classlistChunk, options: [], range: NSRange(classlistChunk.startIndex..., in: classlistChunk))
    let refedClsResults = classNameReg.matches(in: classrefsChunk, options: [], range: NSRange(classrefsChunk.startIndex..., in: classrefsChunk))
    
    for allClsResult in allClsResults {
        let cls = String(classlistChunk[Range(allClsResult.range(at: 1), in: classlistChunk)!])
        if cls.isEmpty { continue }
        allClsName.insert(cls)
    }
    
    for refedClsResult in refedClsResults {
        let cls = String(classrefsChunk[Range(refedClsResult.range(at: 1), in: classrefsChunk)!])
        if cls.isEmpty { continue }
        refedClsName.insert(cls)
    }
    
    let unusedCls = allClsName.subtracting(refedClsName)
    return Array(unusedCls).sorted(by: <)
}

private func printParams() {
    print("🔅 参数一: mach-o文件绝对路径。")
    print("🔅 参数二: 检查输出文件路径。文件后缀必须是html格式。")
    print("🔅 参数二: Selector白名单数组。")
}

let arguments = CommandLine.arguments
print("⚠️ arguments: \(arguments)")
guard arguments.count >= 4 else {
    printParams()
    exit(1)
}

guard let machoPath = verifiedMachOPath(arguments[1]) else {
    print("请输入正确的mach文件")
    printParams()
    exit(1)
}

let outputPath = arguments[2]

guard let data = arguments[3].data(using: .utf8), let selWhiteList = try JSONSerialization.jsonObject(with: data, options: []) as? [String] else {
    print("Selector白名单必须是合法的字符传数组")
    printParams()
    exit(1)
}

let machoInfo = systemCall(launchPath: "/usr/bin/otool", arguments: ["-oV", machoPath]) ?? ""

let unusedClass = findUnusedClass(machoInfo: machoInfo)
let unusedMethod = findUnusedMethods(machoPath: machoPath, machoInfo: machoInfo, selWhiteList: selWhiteList)

var html = """
<html> \
<head>\
<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\
<title>Mach-O文件分析</title>\
<style type=\"text/css\">\
table {\
width: 100%;\
border-right:1px solid #490;\
border-bottom:1px solid #490;\
}\
table td{\
border-left:1px solid #490;\
border-top:1px solid #490;\
}\
</style>\
</head>\
<body>
"""

html += "<div><h2>可能未使用的方法</h2><table>"
for m in unusedMethod {
    html += "<tr><td>\(m)</td></tr>"
}
html += "</table></div>"


html += "<div><h2>可能未使用的类</h2><table>"
for cls in unusedClass {
    html += "<tr><td>\(cls)</td></tr>"
}
html += "</table></div>"

html += "</body></html>"

try? html.write(toFile: outputPath, atomically: true, encoding: .utf8)
