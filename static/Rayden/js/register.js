$(function()
  {
 var validator = $('#regform').validate(
      {
        rules:
        {
          email: {required:true,
                      regex:true},
          phoneno: {required:true,
                      regex:true},
          password: {required:true,
                      regex:true}
        },
        messages:
        {
          email: {required:"Please enter a email",
                      regex: "Please enter a valid email"} ,
          phoneno: {required:"Please enter a phone number", 
                      regex: "Please enter a valid phone number"},
          password: {required:"Please enter a password", 
                      regex: "Password must contain at least 8 characters, 1 uppercase letter, 1 number and 1 special character"}        
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
    
    $("#email").rules("add", { regex: /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/ })
    $("#phoneno").rules("add", { regex: /^[8|9]\d{7}$/ })
    $("#pw").rules("add", { regex: /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/})
    
  });