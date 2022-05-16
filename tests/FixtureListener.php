<?php

use PHPUnit\Framework\TestListener;
use PHPUnit\Framework\TestSuite;
use PHPUnit\Framework\Test;
use PHPUnit\Framework\AssertionFailedError;
use Strukt\Fs;

class FixtureListener implements TestListener
{
    // protected $suites = ['UserIntegrationTest', 'AccountIntegrationTest'];

    public function addWarning(Test $test, Throwable $e, float $time):void{}
    public function addError(Test $test, Throwable $e, float $time):void{}
    public function addFailure(Test $test, AssertionFailedError $e, float $time):void{}
    public function addIncompleteTest(Test $test, Throwable $e, float $time):void{}
    public function addRiskyTest(Test $test, Throwable $e, float $time):void{}
    public function addSkippedTest(Test $test, Throwable $e, float $time):void{}
    public function startTest(Test $test):void{}
    public function endTest(Test $test, float $time):void{}

    public function startTestSuite(TestSuite $suite):void{

        if(!Fs::isPath("fixture/pitsolu")){
            
            exec("./console cry:keys --name pitsolu");
            exec("./console cert:selfsign -k pitsolu -o cacert.pem");
            exec("mv pitsolu ./fixture");
            exec("mv pitsolu.pub ./fixture");
            exec("mv cacert.pem ./fixture");
        }
    }

    public function endTestSuite(TestSuite $suite):void{

        //
    }
}