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
	     .to.throw(SyntaxError)
       .to.match(/^SyntaxError: At least one argument is needed - the maxtime$/);
    });

    it("Will throw a RangeError exception if maxtime argument is less than zero", function() {
      expect(function() { Scrypt.ParamsSync(-1); })
	      .to.throw(RangeError)
        .to.match(/^RangeError: maxtime must be greater than 0$/);
    });

    it("Will throw a TypeError exception if maxmem is not an integer", function() {
    	expect(function() { Scrypt.ParamsSync(1, 2.4); })
    		.to.throw(TypeError)
    		.to.match(/^TypeError: maxmem must be an integer$/);
    });

    it("Will throw a RangeError exception if maxmem is less than 0", function() {
    	expect(function() { Scrypt.ParamsSync(1, -2); })
    		.to.throw(RangeError)
    		.to.match(/^RangeError: maxmem must be greater than or equal to 0$/);
    });

    it("Will throw a RangeError exception if max_memfrac is not between 0.0 and 1.0", function() {
    	expect(function() { Scrypt.ParamsSync(1, 2, -0.1); })
    		.to.throw(RangeError)
    		.to.match(/^RangeError: max_memfrac must be between 0.0 and 1.0 inclusive$/);

    	expect(function() { Scrypt.ParamsSync(1, 2, 1.1); })
    		.to.throw(RangeError)
    		.to.match(/^RangeError: max_memfrac must be between 0.0 and 1.0 inclusive$/);
    });

    it("Will throw a TypeError if any arguments are not numbers", function() {
    	var args = [1, 2, 0.9];

    	for (var i=0; i < args.length; i++) {
    		var temp = args[i];
    		args[i] = "not a number";
    		expect(function() { Scrypt.ParamsSync(args[0], args[1], args[2]); })
    			.to.throw(TypeError)
    			.to.match(/^TypeError: (maxtime|maxmem|max_memfrac) must be a number$/);

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
	     .to.throw(SyntaxError)
       .to.match(/^SyntaxError: No arguments present$/);
    });

    it("Will throw a SyntaxError if no callback function is present", function() {
      expect(function() {Scrypt.Params(1);})
        .to.throw(SyntaxError)
        .to.match(/^SyntaxError: No callback function present$/);
    })

    it("Will throw a SyntaxError if callback function is the first argument present", function() {
      expect(function() {Scrypt.Params(function(){});})
        .to.throw(SyntaxError)
        .to.match(/^SyntaxError: At least one argument is needed before the callback - the maxtime$/);
    })

    it("Will throw a RangeError exception if maxtime argument is less than zero", function() {
      expect(function() { Scrypt.Params(-1, function(){}); })
	      .to.throw(RangeError)
        .to.match(/^RangeError: maxtime must be greater than 0$/);
    });

    it("Will throw a TypeError exception if maxmem is not an integer", function() {
    	expect(function() { Scrypt.Params(1, 2.4, function(){}); })
    		.to.throw(TypeError)
    		.to.match(/^TypeError: maxmem must be an integer$/);
    });

    it("Will throw a RangeError exception if maxmem is less than 0", function() {
    	expect(function() { Scrypt.Params(1, -2, function(){}); })
    		.to.throw(RangeError)
    		.to.match(/^RangeError: maxmem must be greater than or equal to 0$/);
    });

    it("Will throw a RangeError exception if max_memfrac is not between 0.0 and 1.0", function() {
    	expect(function() { Scrypt.Params(1, 2, -0.1, function(){}); })
    		.to.throw(RangeError)
    		.to.match(/^RangeError: max_memfrac must be between 0.0 and 1.0 inclusive$/);

    	expect(function() { Scrypt.Params(1, 2, 1.1, function(){}); })
    		.to.throw(RangeError)
    		.to.match(/^RangeError: max_memfrac must be between 0.0 and 1.0 inclusive$/);
    });

    it("Will throw a TypeError if any arguments are not numbers", function() {
    	var args = [1, 2, 0.9];

    	for (var i=0; i < args.length; i++) {
    		var temp = args[i];
    		args[i] = "not a number";
    		expect(function() { Scrypt.Params(args[0], args[1], args[2], function(){}); })
    			.to.throw(TypeError)
    			.to.match(/^TypeError: (maxtime|maxmem|max_memfrac) must be a number$/);

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

describe("Scrypt KDF Function", function() {
  describe("Synchronous functionality with incorrect arguments", function(){
    it("Will throw SyntexError exception if called without arguments", function () {
     expect(Scrypt.KDFSync)
	     .to.throw(SyntaxError)
       .to.match(/^SyntaxError: At least two arguments are needed - the key and the Scrypt paramaters object$/);
    });

    it("Will throw a TypeError if the key is not a string or a Buffer object", function() {
      expect(function(){Scrypt.KDFSync(1123, {N:1, r:1, p:1})})
        .to.throw(TypeError)
        .to.match(/^TypeError: key type is incorrect: It can only be of type string or Buffer$/);
    })

    it("Will throw a TypeError if the Scrypt params object is incorrect", function() {
      expect(function(){Scrypt.KDFSync("password", {N:1, p:1})})
        .to.throw(TypeError)
        .to.match(/^TypeError: Scrypt params object does not have 'r' property present$/);
    })
  });

  describe("Synchronous functionality with correct arguments", function() {
    it("Will return a buffer object containing the KDF with a string input", function() {
      var result = Scrypt.KDFSync("password", {N:1, r:1, p:1});
      expect(result)
        .to.be.an.instanceof(Buffer);
      expect(result)
        .to.have.length.above(0);
    })

    it("Will use random salt to ensure no two KDFs are the same, even if the keys are identical", function(){
      var result1 = Scrypt.KDFSync("password", {N:1, r:1, p:1})
        , result2 = Scrypt.KDFSync("password", {N:1, r:1, p:1});

      expect(result1.toString("base64"))
        .to.not.equal(result2.toString("base64"));
    })
  });

  describe("Asyncrhonous functionality with incorrect arguments", function() {
    it("Will throw SyntexError exception if called without arguments", function () {
      expect(Scrypt.KDF)
        .to.throw(SyntaxError)
        .to.match(/^SyntaxError: No arguments present$/);
    });

    it("Will throw a TypeError if the key is not a string or a Buffer object", function() {
      expect(function(){Scrypt.KDF(1123, {N:1, r:1, p:1}, function(){})})
        .to.throw(TypeError)
        .to.match(/^TypeError: key type is incorrect: It can only be of type string or Buffer$/);
    })

    it("Will throw a TypeError if the Scrypt params object is incorrect", function() {
      expect(function(){Scrypt.KDF("password", {N:1, r:1}, function(){})})
        .to.throw(TypeError)
        .to.match(/^TypeError: Scrypt params object does not have 'p' property present$/);
    })
  });

  describe("Asynchronous functionality with correct arguments", function() {
    it("Will return a buffer object containing the KDF with a buffer input", function(done) {
      Scrypt.KDF(new Buffer("password"), {N:1, r:1, p:1}, function(err, result) {
        expect(result)
          .to.be.an.instanceof(Buffer);
        expect(result)
          .to.have.length.above(0);
        expect(err)
          .to.not.exist;
        done();
      });
    })

    it("Will use random salt to ensure no two KDFs are the same, even if the keys are identical", function(done) {
      Scrypt.KDF("password", {N:1, r:1, p:1}, function(err, result1) {
        expect(err)
          .to.not.exist;
        Scrypt.KDF("password", {N:1, r:1, p:1}, function(err, result2) {
          expect(err)
            .to.not.exist;
          expect(result1.toString("base64"))
            .to.not.equal(result2.toString("base64"));
          done();
        });
      });
    });
  });
});
