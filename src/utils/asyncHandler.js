//**************by promises */
const asyncHandler = (requestHandler) => {
  return (req, res, next) => {
    Promise.resolve(requestHandler(req, res, next)).catch((err) => next(err));
  };
};

export { asyncHandler };

//****************by tryCatch */

// const asyncHandler=()=>{}
// const asyncHandler=(func)=>{()=>{}}
// const asyncHandler=(func)=>async()=>{}     explaination

//const asyncHandler=(fn)=>async(error,req,res,next)=>{}

// const asyncHandler = (fn) => async (req, res, next) => {
//   try {
//     await fn(req, res, next);
//   } catch (error) {
//     res.status(error.code || 3000).json({
//       success: false,
//       message: error.message,
//     });
//   }
// };
