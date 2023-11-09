$(function()
  {
 var validator = $('#confirm').validate(
      {
        rules:
        {
          cfmEmail: {required:true,
                      regex:true},
        },
        messages:
        {
          cfmEmail: {required:"Please enter a email",
                      regex: "Please enter a valid email"}
        },
        errorPlacement: function(error, element) 
        {
            error.insertAfter( element.closest('.wrap-input100') );
         }
      });
    
    $.validator.addMethod(
        "regex",
        function(value, element, regexp) {
            var re = new RegExp(regexp);
            return this.optional(element) || re.test(value);
        },
        "Please check your input."
);
    
    $("#cfmEmail").rules("add", { regex: /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/ })    
  });