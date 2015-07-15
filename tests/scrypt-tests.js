var assert = require("chai").assert
  , expect = require("chai").expect
  , Scrypt = require("../");

describe("Scrypt Params", function() {
  //Examines a returned Params JSON object
  var examine = function(obj, err) {
    expect(err)
      .to.not.exist;

    expect(obj)
      .to.be.a("Object")
      .and.to.have.all.keys("N","r","p");

    expect(obj)
      .to.have.property("N")
      .and.to.be.a("Number");

    expect(obj)
      .to.have.property("r")
      .and.to.be.a("Number");

    expect(obj)
      .to.have.property("p")
      .and.to.be.a("Number");
  }

  describe("Synchronous functionality with incorrect arguments", function () {
    it("Will throw SyntexError exception if called without arguments", function () {
     expect(Scrypt.ParamsSync)
	     .to.throw(Error)
       .to.match(/^SyntaxError: No arguments present, at least one argument is needed - the maxtime$/)
       .to.have.property("name","SyntaxError");
    });

    it("Will throw a RangeError exception if maxtime argument is less than zero", function() {
      expect(function() { Scrypt.ParamsSync(-1); })
	      .to.throw(Error)
        .to.match(/^RangeError: maxtime must be greater than 0$/)
        .to.have.property("name","RangeError");
    });

    it("Will throw a TypeError exception if maxmem is not an integer", function() {
    	expect(function() { Scrypt.ParamsSync(1, 2.4); })
    		.to.throw(Error)
    		.to.match(/^TypeError: maxmem must be an integer$/)
    		.to.have.property("name","TypeError");
    });

    it("Will throw a RangeError exception if maxmem is less than 0", function() {
    	expect(function() { Scrypt.ParamsSync(1, -2); })
    		.to.throw(Error)
    		.to.match(/^RangeError: maxmem must be greater than or equal to 0$/)
    		.to.have.property("name","RangeError");
    });

    it("Will throw a RangeError exception if max_memfrac is not between 0.0 and 1.0", function() {
    	expect(function() { Scrypt.ParamsSync(1, 2, -0.1); })
    		.to.throw(Error)
    		.to.match(/^RangeError: max_memfrac must be between 0.0 and 1.0 inclusive$/)
    		.to.have.property("name","RangeError");

    	expect(function() { Scrypt.ParamsSync(1, 2, 1.1); })
    		.to.throw(Error)
    		.to.match(/^RangeError: max_memfrac must be between 0.0 and 1.0 inclusive$/)
    		.to.have.property("name","RangeError");
    });

    it("Will throw a TypeError if any arguments are not numbers", function() {
    	var args = [1, 2, 0.9];

    	for (var i=0; i < args.length; i++) {
    		var temp = args[i];
    		args[i] = "not a number";
    		expect(function() { Scrypt.ParamsSync(args[0], args[1], args[2]); })
    			.to.throw(Error)
    			.to.match(/^TypeError: (maxtime|maxmem|max_memfrac) must be a number$/)
    			.to.have.property("name","TypeError");

        args[i] = temp;
    	}
    });
  });

  describe("Synchronous functionality with correct arguments", function() {
    it("Should return a JSON object when only maxtime is defined", function() {
    	var params = Scrypt.ParamsSync(1);
      examine(params);
    });

    it("Should return a JSON object when only maxtime and maxmem are defined", function() {
    	var params = Scrypt.ParamsSync(1, 2);
      examine(params);
    });

    it("Should return a JSON object when maxtime, maxmem and max_memfrac are defined", function() {
    	var params = Scrypt.ParamsSync(1, 2, 0.5);
      examine(params);
    });
  });

  describe("Asynchronous functionality with incorrect arguments", function() {
    it("Will throw SyntexError exception if called without arguments", function () {
     expect(Scrypt.Params)
	     .to.throw(Error)
       .to.match(/^SyntaxError: No arguments present, at least two arguments are needed - the maxtime and callback function$/)
       .to.have.property("name","SyntaxError");
    });

    it("Will throw a SyntaxError if no callback function is present", function() {
      expect(function() {Scrypt.Params(1);})
        .to.throw(Error)
        .to.match(/^SyntaxError: No callback function present$/)
        .to.have.property("name","SyntaxError");
    })

    it("Will throw a SyntaxError if callback function is the first argument present", function() {
      expect(function() {Scrypt.Params(function(){});})
        .to.throw(Error)
        .to.match(/^SyntaxError: At least one argument is needed before the callback - the maxtime$/)
        .to.have.property("name","SyntaxError");
    })

    it("Will throw a RangeError exception if maxtime argument is less than zero", function() {
      expect(function() { Scrypt.Params(-1, function(){}); })
	      .to.throw(Error)
        .to.match(/^RangeError: maxtime must be greater than 0$/)
        .to.have.property("name","RangeError");
    });

    it("Will throw a TypeError exception if maxmem is not an integer", function() {
    	expect(function() { Scrypt.Params(1, 2.4, function(){}); })
    		.to.throw(Error)
    		.to.match(/^TypeError: maxmem must be an integer$/)
    		.to.have.property("name","TypeError");
    });

    it("Will throw a RangeError exception if maxmem is less than 0", function() {
    	expect(function() { Scrypt.Params(1, -2, function(){}); })
    		.to.throw(Error)
    		.to.match(/^RangeError: maxmem must be greater than or equal to 0$/)
    		.to.have.property("name","RangeError");
    });

    it("Will throw a RangeError exception if max_memfrac is not between 0.0 and 1.0", function() {
    	expect(function() { Scrypt.Params(1, 2, -0.1, function(){}); })
    		.to.throw(Error)
    		.to.match(/^RangeError: max_memfrac must be between 0.0 and 1.0 inclusive$/)
    		.to.have.property("name","RangeError");

    	expect(function() { Scrypt.Params(1, 2, 1.1, function(){}); })
    		.to.throw(Error)
    		.to.match(/^RangeError: max_memfrac must be between 0.0 and 1.0 inclusive$/)
    		.to.have.property("name","RangeError");
    });

    it("Will throw a TypeError if any arguments are not numbers", function() {
    	var args = [1, 2, 0.9];

    	for (var i=0; i < args.length; i++) {
    		var temp = args[i];
    		args[i] = "not a number";
    		expect(function() { Scrypt.Params(args[0], args[1], args[2], function(){}); })
    			.to.throw(Error)
    			.to.match(/^TypeError: (maxtime|maxmem|max_memfrac) must be a number$/)
    			.to.have.property("name","TypeError");

        args[i] = temp;
    	}
    });
  });

  describe("Asynchronous functionality with correct arguments", function() {
    it("Should return a JSON object when only maxtime is defined", function(done) {
      Scrypt.Params(1, function(err, params) {
        examine(params, err);
        done();
      });
    });

    it("Should return a JSON object when only maxtime and maxmem are defined", function(done) {
      Scrypt.Params(1, 2, function(err, params){
        examine(params, err);
        done();
      });
    });

    it("Should return a JSON object when maxtime, maxmem and max_memfrac are defined", function(done) {
      Scrypt.Params(1, 2, 0.5, function(err, params){
        examine(params, err);
        done();
      });
    });
  });
});
