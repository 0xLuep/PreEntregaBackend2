import CustomRouter from "../../utils/CustomRouter.util.js";
import passportCb from "../../middlewares/passportCb.mid.js";
import { createProduct, readProducts, updateProduct, destroyProduct } from "../../controllers/products.controller.js";


class ProductsApiRouter extends CustomRouter {
    constructor() {
        super();
        this.init();
    }
    init = () => {
        this.read('/', ['PUBLIC'], readProducts);
        this.create('/', ['ADMIN'], passportCb('admin'), createProduct);
        this.update('/:id', ['ADMIN'], passportCb('admin'), updateProduct);
        this.destroy('/:id', ['ADMIN'], passportCb('admin'), destroyProduct);
    };
}

const productsApiRouter = new ProductsApiRouter();
export default productsApiRouter.getRouter();