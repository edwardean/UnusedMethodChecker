import XCTest

import UnusedMethodCheckerTests

var tests = [XCTestCaseEntry]()
tests += UnusedMethodCheckerTests.allTests()
XCTMain(tests)